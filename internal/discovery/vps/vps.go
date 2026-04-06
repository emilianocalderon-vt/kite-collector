// Package vps provides discovery sources for VPS hosting providers.
// Each source implements [discovery.Source] and enumerates servers/instances
// from the provider's API. All connectors use raw net/http + JSON — no
// vendor SDKs.
package vps

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	maxRetryAttempts = 3
	baseRetryDelay   = 1 * time.Second
	maxRetryDelay    = 30 * time.Second
	clientTimeout    = 30 * time.Second
)

// authError is returned for 401/403 responses. The caller should skip
// this source rather than retry.
type authError struct {
	body       string
	statusCode int
}

func (e *authError) Error() string {
	return fmt.Sprintf("authentication error (%d): %s", e.statusCode, truncate(e.body, 200))
}

// authFunc sets authentication headers on an outgoing HTTP request.
type authFunc func(req *http.Request)

// bearerAuth returns an authFunc that sets a Bearer token header.
func bearerAuth(token string) authFunc {
	return func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

// apiClient is a shared HTTP client for VPS provider APIs with retry,
// rate-limit handling, and JSON response decoding.
type apiClient struct {
	http *http.Client
	auth authFunc
	base string
	name string
}

// newClient creates a new API client for the named provider.
func newClient(name, base string, auth authFunc) *apiClient {
	return &apiClient{
		name: name,
		base: base,
		auth: auth,
		http: &http.Client{Timeout: clientTimeout},
	}
}

// get performs an authenticated GET request and JSON-decodes the response
// body into out. Transient errors are retried with exponential backoff.
func (c *apiClient) get(ctx context.Context, path string, out any) error {
	resp, err := c.doWithRetry(ctx, func() (*http.Response, error) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil) //#nosec G704 -- base URL is hardcoded per provider
		if reqErr != nil {
			return nil, reqErr
		}
		c.auth(req)
		req.Header.Set("Accept", "application/json")
		return c.http.Do(req) //#nosec G704 -- request built from internal base URL
	})
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return json.NewDecoder(resp.Body).Decode(out)
}

// doWithRetry executes fn up to maxRetryAttempts times with exponential
// backoff. Response classification:
//   - 2xx: success
//   - 401/403: authError (non-retryable)
//   - 429: retry, honouring Retry-After header
//   - 5xx: retry
//   - other 4xx: immediate failure
func (c *apiClient) doWithRetry(ctx context.Context, fn func() (*http.Response, error)) (*http.Response, error) {
	var lastErr error

	for attempt := range maxRetryAttempts {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if attempt > 0 {
			delay := retryBackoff(attempt)
			slog.Debug(c.name+": retrying",
				"attempt", attempt+1,
				"delay", delay,
			)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		resp, err := fn()
		if err != nil {
			lastErr = fmt.Errorf("%s: request failed: %w", c.name, err)
			slog.Warn(c.name+": network error, will retry",
				"attempt", attempt+1,
				"error", err,
			)
			continue
		}

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return resp, nil

		case resp.StatusCode == 401 || resp.StatusCode == 403:
			body := drainBody(resp, 500)
			return nil, &authError{statusCode: resp.StatusCode, body: body}

		case resp.StatusCode == 429:
			retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
			body := drainBody(resp, 200)
			lastErr = fmt.Errorf("%s: rate limited (429): %s", c.name, body)
			slog.Warn(c.name+": rate limited",
				"attempt", attempt+1,
				"retry_after", retryAfter,
			)
			if retryAfter > 0 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(retryAfter):
				}
			}
			continue

		case resp.StatusCode >= 500:
			body := drainBody(resp, 500)
			lastErr = fmt.Errorf("%s: server error (%d): %s", c.name, resp.StatusCode, body)
			slog.Warn(c.name+": server error, will retry",
				"attempt", attempt+1,
				"status", resp.StatusCode,
			)
			continue

		default:
			body := drainBody(resp, 500)
			return nil, fmt.Errorf("%s: unexpected status %d: %s", c.name, resp.StatusCode, body)
		}
	}

	return nil, fmt.Errorf("%s: exhausted %d retry attempts: %w", c.name, maxRetryAttempts, lastErr)
}

// retryBackoff returns an exponential backoff delay capped at maxRetryDelay.
func retryBackoff(attempt int) time.Duration {
	delay := time.Duration(float64(baseRetryDelay) * math.Pow(2, float64(attempt-1)))
	if delay > maxRetryDelay {
		delay = maxRetryDelay
	}
	return delay
}

// parseRetryAfter parses a Retry-After header value (seconds or HTTP-date).
// Returns 0 when the header is missing or unparseable.
func parseRetryAfter(val string) time.Duration {
	if val == "" {
		return 0
	}
	if secs, err := strconv.Atoi(val); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(val); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// drainBody reads up to maxLen bytes from the response body, closes it, and
// returns the content as a string.
func drainBody(resp *http.Response, maxLen int) string {
	if resp.Body == nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, int64(maxLen)))
	return string(data)
}

// truncate returns at most n bytes of s.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// sanitizeLogValue replaces control characters to prevent log injection (CWE-117).
func sanitizeLogValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}

// toJSON marshals v to a JSON string. Returns "{}" on error.
func toJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(data)
}
