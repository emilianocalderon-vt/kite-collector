package envelope

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// JWKSClient fetches and caches the server's JWKS for payload encryption.
// Keys are refreshed hourly or on kid mismatch.
type JWKSClient struct {
	lastFetch time.Time
	logger    *slog.Logger
	keys      map[string]jose.JSONWebKey
	client    *http.Client
	url       string
	ttl       time.Duration
	mu        sync.RWMutex
}

// NewJWKSClient creates a JWKS client that caches keys from the given URL.
func NewJWKSClient(url string, logger *slog.Logger) *JWKSClient {
	if logger == nil {
		logger = slog.Default()
	}
	return &JWKSClient{
		url:    url,
		logger: logger,
		keys:   make(map[string]jose.JSONWebKey),
		client: &http.Client{Timeout: 10 * time.Second},
		ttl:    1 * time.Hour,
	}
}

// GetKey returns the server JWK with the given kid. If the key is not
// cached or the cache is stale, it fetches from the JWKS endpoint.
func (c *JWKSClient) GetKey(ctx context.Context, kid string) (jose.JSONWebKey, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	stale := time.Since(c.lastFetch) > c.ttl
	c.mu.RUnlock()

	if ok && !stale {
		return key, nil
	}

	// Refresh the cache.
	if err := c.refresh(ctx); err != nil {
		// If refresh fails but we have a cached key, use it.
		if ok {
			c.logger.Warn("JWKS refresh failed, using cached key", "kid", kid, "error", err)
			return key, nil
		}
		return jose.JSONWebKey{}, fmt.Errorf("fetch JWKS: %w", err)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok = c.keys[kid]
	if !ok {
		return jose.JSONWebKey{}, fmt.Errorf("key %q not found in JWKS at %s", kid, c.url)
	}
	return key, nil
}

// GetEncryptionKey returns the first key with use=enc from the cache.
// Fetches the JWKS if the cache is empty or stale.
func (c *JWKSClient) GetEncryptionKey(ctx context.Context) (jose.JSONWebKey, error) {
	c.mu.RLock()
	stale := time.Since(c.lastFetch) > c.ttl
	empty := len(c.keys) == 0
	c.mu.RUnlock()

	if stale || empty {
		if err := c.refresh(ctx); err != nil && empty {
			return jose.JSONWebKey{}, fmt.Errorf("fetch JWKS: %w", err)
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, key := range c.keys {
		if key.Use == "enc" {
			return key, nil
		}
	}
	// If no explicit use=enc, return the first key.
	for _, key := range c.keys {
		return key, nil
	}
	return jose.JSONWebKey{}, fmt.Errorf("no keys in JWKS at %s", c.url)
}

func (c *JWKSClient) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP GET %s: %w", c.url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return fmt.Errorf("read JWKS body: %w", err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = make(map[string]jose.JSONWebKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		c.keys[k.KeyID] = k
	}
	c.lastFetch = time.Now()
	c.logger.Debug("JWKS refreshed", "keys", len(jwks.Keys), "url", c.url)

	return nil
}
