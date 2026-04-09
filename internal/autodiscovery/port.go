package autodiscovery

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vulnertrack/kite-collector/internal/safenet"
)

const (
	defaultPortTimeout = 2 * time.Second
	defaultHTTPTimeout = 3 * time.Second
	maxBodyRead        = 4096 // bytes to read from fingerprint response
)

// openPort records a host:port pair that accepted a TCP connection.
type openPort struct {
	Host string
	Port int
}

// probePorts runs parallel TCP connect probes for every combination of target
// and port.  It returns the list of host:port pairs that accepted a
// connection within the timeout.
func probePorts(ctx context.Context, targets []string, ports []int, timeoutMs int) []openPort {
	timeout := defaultPortTimeout
	if timeoutMs > 0 {
		timeout = time.Duration(timeoutMs) * time.Millisecond
	}

	var (
		mu      sync.Mutex
		results []openPort
		wg      sync.WaitGroup
	)

	for _, target := range targets {
		for _, port := range ports {
			safenet.SafeGo(&wg, slog.Default(), "autodiscovery-probe-port", func() {
				if ctx.Err() != nil {
					return
				}

				addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
				d := net.Dialer{Timeout: timeout}
				conn, err := d.DialContext(ctx, "tcp", addr)
				if err != nil {
					return
				}
				_ = conn.Close()

				mu.Lock()
				results = append(results, openPort{Host: target, Port: port})
				mu.Unlock()
			})
		}
	}

	wg.Wait()
	return results
}

// fingerprintOpenPorts attempts HTTP fingerprinting for each open port,
// matching against known service signatures.  Only services confirmed by the
// fingerprint are returned.
func fingerprintOpenPorts(ctx context.Context, open []openPort, services []ServiceSignature, httpTimeoutMs int) []DiscoveredService {
	httpTimeout := defaultHTTPTimeout
	if httpTimeoutMs > 0 {
		httpTimeout = time.Duration(httpTimeoutMs) * time.Millisecond
	}

	lookup := servicesByPort(services)

	var (
		mu      sync.Mutex
		results []DiscoveredService
		wg      sync.WaitGroup
	)

	for _, op := range open {
		candidates, ok := lookup[op.Port]
		if !ok {
			continue
		}
		for _, sig := range candidates {
			safenet.SafeGo(&wg, slog.Default(), "autodiscovery-fingerprint", func() {
				if ctx.Err() != nil {
					return
				}

				endpoint := buildEndpoint(op.Host, op.Port, sig.TLS)
				if sig.FingerprintPath == "" || sig.FingerprintMatch == "" {
					// No HTTP fingerprint possible — report as detected.
					status, missing := determineStatus(sig)
					if status == "ready" {
						status = "detected"
					}
					mu.Lock()
					results = append(results, DiscoveredService{
						Name:        sig.Name,
						DisplayName: sig.DisplayName,
						Endpoint:    endpoint,
						Method:      "port_scan",
						Status:      status,
						Credentials: missing,
						SetupHint:   sig.SetupHint,
					})
					mu.Unlock()
					return
				}

				confirmed, version := fingerprint(ctx, endpoint, sig.FingerprintPath, sig.FingerprintMatch, httpTimeout)
				if !confirmed {
					return
				}

				if !sig.TLS {
					slog.Warn("autodiscovery: service discovered via insecure (non-TLS) probe — consider enabling TLS",
						"service", sig.Name,
						"endpoint", endpoint,
					)
				}

				slog.Info("autodiscovery: service confirmed by fingerprint",
					"service", sig.Name,
					"endpoint", endpoint,
					"version", version,
				)

				status, missing := determineStatus(sig)
				mu.Lock()
				results = append(results, DiscoveredService{
					Name:        sig.Name,
					DisplayName: sig.DisplayName,
					Endpoint:    endpoint,
					Method:      "port_scan",
					Status:      status,
					Credentials: missing,
					SetupHint:   sig.SetupHint,
					Version:     version,
				})
				mu.Unlock()
			})
		}
	}

	wg.Wait()
	return results
}

// fingerprint sends an HTTP GET to endpoint+path and returns true if the
// response body or relevant headers contain the match substring.  It also
// extracts a version string from the response body if available.
func fingerprint(ctx context.Context, endpoint, path, match string, timeout time.Duration) (bool, string) {
	url := strings.TrimRight(endpoint, "/") + path

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //#nosec G402 -- self-signed certs common in infrastructure services
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, ""
	}
	req.Header.Set("User-Agent", "kite-collector/autodiscovery")

	resp, err := client.Do(req) //#nosec G107 -- URL built from known service endpoints
	if err != nil {
		// If HTTPS failed, try HTTP (or vice versa).
		return false, ""
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	if err != nil {
		return false, ""
	}

	content := string(body)

	// Check body.
	if match != "" && strings.Contains(content, match) {
		return true, extractVersion(content, resp.Header)
	}

	// Check Server and X-Powered-By headers.
	for _, hdr := range []string{"Server", "X-Powered-By"} {
		if match != "" && strings.Contains(resp.Header.Get(hdr), match) {
			return true, extractVersion(content, resp.Header)
		}
	}

	return false, ""
}

// extractVersion attempts to extract a version string from a fingerprint
// response.  It checks the Server header first, then scans the body for
// common JSON version field patterns.
func extractVersion(body string, headers http.Header) string {
	// Server header often contains "ProductName/version".
	if server := headers.Get("Server"); server != "" {
		if idx := strings.LastIndexByte(server, '/'); idx >= 0 && idx < len(server)-1 {
			return server[idx+1:]
		}
	}

	// Scan body for common JSON version keys.
	for _, prefix := range []string{
		`"version":"`, `"Version":"`,
		`"version": "`, `"Version": "`,
		`"api_version":"`, `"api_version": "`,
		`"ApiVersion":"`, `"ApiVersion": "`,
		`"pveversion":"`, `"pveversion": "`,
	} {
		idx := strings.Index(body, prefix)
		if idx < 0 {
			continue
		}
		start := idx + len(prefix)
		end := strings.IndexByte(body[start:], '"')
		if end > 0 && end < 64 {
			return body[start : start+end]
		}
	}

	return ""
}

// buildEndpoint constructs a URL from host, port, and TLS preference.
func buildEndpoint(host string, port int, useTLS bool) string {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}
