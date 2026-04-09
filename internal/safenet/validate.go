package safenet

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// options configures endpoint validation behavior.
type options struct {
	allowHTTP    bool
	allowPrivate bool
}

// Option configures ValidateEndpoint behavior.
type Option func(*options)

// AllowHTTP permits HTTP scheme (default: HTTPS only).
func AllowHTTP() Option { return func(o *options) { o.allowHTTP = true } }

// AllowPrivate permits private, loopback, and link-local IP addresses.
func AllowPrivate() Option { return func(o *options) { o.allowPrivate = true } }

// ValidateEndpoint checks that a URL is safe to connect to.
// Rejects non-HTTPS schemes (unless AllowHTTP), localhost, link-local,
// and private IPs (unless AllowPrivate).
func ValidateEndpoint(raw string, opts ...Option) (*url.URL, error) {
	var cfg options
	for _, o := range opts {
		o(&cfg)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", raw, err)
	}

	switch u.Scheme {
	case "https":
		// always allowed
	case "http":
		if !cfg.allowHTTP {
			return nil, fmt.Errorf("URL %q uses HTTP; HTTPS required "+
				"(set AllowHTTP option for local development)", raw)
		}
	case "":
		return nil, fmt.Errorf("URL %q has no scheme; provide a full URL with https://", raw)
	default:
		return nil, fmt.Errorf("URL %q has disallowed scheme %q; "+
			"only https (or http with opt-in) is permitted", raw, u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("URL %q has no host", raw)
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no IP addresses for %q", host)
	}

	if !cfg.allowPrivate {
		for _, addr := range addrs {
			if addr.IP.IsLoopback() || addr.IP.IsLinkLocalUnicast() ||
				addr.IP.IsLinkLocalMulticast() || addr.IP.IsPrivate() {
				return nil, fmt.Errorf("URL %q resolves to private/local "+
					"address %s; set AllowPrivate() for local services", raw, addr.IP)
			}
		}
	}

	return u, nil
}

// SanitizePathSegment validates that an ID is safe to use in a URL path.
// Rejects path traversal, URL-encoded dots, slashes, and control characters.
// Only allows [a-zA-Z0-9._-].
func SanitizePathSegment(id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("empty path segment")
	}

	decoded, err := url.PathUnescape(id)
	if err != nil {
		return "", fmt.Errorf("invalid path segment %q: %w", id, err)
	}

	if strings.Contains(decoded, "..") || strings.Contains(decoded, "/") ||
		strings.Contains(decoded, "\\") {
		return "", fmt.Errorf("path traversal detected in %q", id)
	}

	for _, r := range decoded {
		if !isPathSafe(r) {
			return "", fmt.Errorf("unsafe character %q in path segment %q", r, id)
		}
	}

	return decoded, nil
}

func isPathSafe(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.'
}
