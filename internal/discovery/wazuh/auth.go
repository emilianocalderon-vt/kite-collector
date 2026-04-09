// Package wazuh implements a discovery.Source that enumerates agents, installed
// packages, and detected vulnerabilities from the Wazuh Manager REST API using
// JWT authentication. No vendor SDK — raw HTTP + JSON only.
package wazuh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vulnertrack/kite-collector/internal/safenet"
)

const (
	// defaultTokenLifetime is the default JWT token lifetime in Wazuh (900s).
	defaultTokenLifetime = 900 * time.Second

	// tokenRefreshBuffer is how early before expiry we proactively refresh.
	tokenRefreshBuffer = 60 * time.Second
)

// wazuhAuth handles JWT authentication with the Wazuh Manager API.
// It caches the token and transparently refreshes it before expiry.
type wazuhAuth struct {
	expiry   time.Time
	client   *http.Client
	endpoint string
	username string
	password string
	token    string
	mu       sync.Mutex
}

// newAuth creates a new wazuhAuth instance.
// Password is cloned to ensure heap allocation for ZeroString safety.
func newAuth(endpoint, username, password string, client *http.Client) *wazuhAuth {
	return &wazuhAuth{
		endpoint: endpoint,
		username: username,
		password: strings.Clone(password),
		client:   client,
	}
}

// getToken returns a valid JWT token, refreshing it if necessary.
// Thread-safe via mutex.
func (a *wazuhAuth) getToken(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Return cached token if still valid (with buffer).
	if a.token != "" && time.Now().Before(a.expiry.Add(-tokenRefreshBuffer)) {
		return a.token, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.endpoint+"/security/user/authenticate", nil)
	if err != nil {
		return "", fmt.Errorf("wazuh auth: build request: %w", err)
	}
	req.SetBasicAuth(a.username, a.password)

	resp, err := a.client.Do(req) //#nosec G107 -- URL from user-configured Wazuh endpoint
	if err != nil {
		return "", fmt.Errorf("wazuh auth: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("wazuh auth: read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("wazuh auth: HTTP %d: %s", resp.StatusCode, truncateStr(string(body), 200))
	}

	var result struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("wazuh auth: decode response: %w", err)
	}

	if result.Data.Token == "" {
		return "", fmt.Errorf("wazuh auth: empty token in response")
	}

	a.token = result.Data.Token
	a.expiry = time.Now().Add(defaultTokenLifetime)

	// Zero password after successful token acquisition (defense-in-depth).
	safenet.ZeroString(&a.password)

	return a.token, nil
}

// invalidateToken clears the cached token, forcing re-authentication
// on the next getToken call.
func (a *wazuhAuth) invalidateToken() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.token = ""
	a.expiry = time.Time{}
}

// isDefaultCredentials returns true when the configured credentials match the
// Wazuh default (wazuh:wazuh). Used to generate a security warning — the
// password is never logged.
func (a *wazuhAuth) isDefaultCredentials() bool {
	return a.username == "wazuh" && a.password == "wazuh"
}
