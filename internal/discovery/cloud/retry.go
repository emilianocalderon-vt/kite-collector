package cloud

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"
)

const (
	defaultMaxAttempts = 3
	defaultBaseDelay   = 1 * time.Second
	defaultMaxDelay    = 30 * time.Second
)

// authError is returned for 401/403 responses, indicating the caller should
// skip the source rather than retry.
type authError struct {
	body       string
	statusCode int
}

func (e *authError) Error() string {
	return fmt.Sprintf("authentication/authorization error (%d): %s", e.statusCode, truncate(e.body, 200))
}

// doWithRetry executes fn up to defaultMaxAttempts times with exponential
// backoff. It classifies HTTP responses as follows:
//   - 2xx: success, return the response
//   - 401/403: return authError (caller should skip this source)
//   - 429: respect Retry-After header, then retry
//   - 5xx: retry with backoff
//   - other 4xx: return immediately (non-retryable client error)
//
// Network errors (fn returns nil response + error) are retried.
// On exhausting all attempts the last error is returned.
func doWithRetry(ctx context.Context, name string, fn func() (*http.Response, error)) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt < defaultMaxAttempts; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if attempt > 0 {
			delay := retryBackoff(attempt)
			slog.Debug(name+": retrying after backoff",
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
			lastErr = fmt.Errorf("%s: request failed: %w", name, err)
			slog.Warn(name+": network error, will retry",
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
			slog.Error(name+": access denied — check IAM permissions",
				"status", resp.StatusCode,
				"hint", iamHint(name),
			)
			return nil, &authError{statusCode: resp.StatusCode, body: body}

		case resp.StatusCode == 429:
			retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
			body := drainBody(resp, 200)
			lastErr = fmt.Errorf("%s: rate limited (429): %s", name, body)
			slog.Warn(name+": rate limited, will retry",
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
			lastErr = fmt.Errorf("%s: server error (%d): %s", name, resp.StatusCode, body)
			slog.Warn(name+": server error, will retry",
				"attempt", attempt+1,
				"status", resp.StatusCode,
			)
			continue

		default:
			body := drainBody(resp, 500)
			return nil, fmt.Errorf("%s: unexpected status %d: %s", name, resp.StatusCode, body)
		}
	}

	return nil, fmt.Errorf("%s: exhausted %d retry attempts: %w", name, defaultMaxAttempts, lastErr)
}

// retryBackoff computes an exponential backoff delay capped at defaultMaxDelay.
func retryBackoff(attempt int) time.Duration {
	delay := time.Duration(float64(defaultBaseDelay) * math.Pow(2, float64(attempt-1)))
	if delay > defaultMaxDelay {
		delay = defaultMaxDelay
	}
	return delay
}

// parseRetryAfter parses the Retry-After header value (seconds or HTTP-date).
// Returns 0 if the header is missing or unparseable.
func parseRetryAfter(val string) time.Duration {
	if val == "" {
		return 0
	}
	// Try seconds first.
	if secs, err := strconv.Atoi(val); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	// Try HTTP-date.
	if t, err := http.ParseTime(val); err == nil {
		d := time.Until(t)
		if d > 0 {
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

// iamHint returns a human-readable remediation hint for authentication errors.
func iamHint(source string) string {
	switch source {
	case "aws_ec2", "aws_sts":
		return "Ensure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are valid. " +
			"For AssumeRole, the source identity must have sts:AssumeRole permission."
	case "gcp_compute":
		return "Ensure the service account has compute.instances.list permission. " +
			"See https://cloud.google.com/compute/docs/access"
	case "azure_vm":
		return "Ensure the service principal has Reader role on the subscription. " +
			"See https://learn.microsoft.com/en-us/azure/role-based-access-control/"
	default:
		return "Check credentials and IAM permissions for " + source
	}
}
