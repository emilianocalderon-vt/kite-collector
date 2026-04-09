package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"gopkg.in/yaml.v3"
)

// SignedConfig is a YAML policy document with an Ed25519 signature.
// The agent pulls this from a static URL (S3/CDN) and verifies
// the signature before applying (RFC-0077 §R10).
type SignedConfig struct {
	// Metadata
	Version   string `yaml:"version"`
	IssuedAt  string `yaml:"issued_at"`
	ExpiresAt string `yaml:"expires_at"`

	// Policy content
	Policy PolicyContent `yaml:"policy"`

	// Ed25519 signature (base64) of the YAML content above (minus the
	// signature field itself).
	Signature string `yaml:"signature"`
}

// PolicyContent defines the configurable policy fields that the SaaS
// can push to agents via signed config pull.
type PolicyContent struct {
	// MinKeyBackend is the minimum acceptable key_backend for enrollment.
	// Values: "file" < "keyring" < "tpm". Empty means no enforcement.
	MinKeyBackend string `yaml:"min_key_backend,omitempty"`

	// ScanInterval overrides the default scan interval.
	ScanInterval string `yaml:"scan_interval,omitempty"`

	// EnabledAuditors lists which audit modules should be active.
	EnabledAuditors []string `yaml:"enabled_auditors,omitempty"`

	// StalenessThreshold overrides the default staleness threshold.
	StalenessThreshold string `yaml:"staleness_threshold,omitempty"`

	// PrivacyMode enforces the tenant's privacy mode on the agent.
	PrivacyMode string `yaml:"privacy_mode,omitempty"`
}

// PullClient fetches and verifies signed policy configs from a static URL.
type PullClient struct {
	policyURL  string
	verifyKey  ed25519.PublicKey
	httpClient *http.Client
}

// NewPullClient creates a policy pull client. policyURL is the HTTPS
// endpoint serving the signed YAML config. verifyKey is the SaaS
// operator's Ed25519 public key for signature verification.
func NewPullClient(policyURL string, verifyKey ed25519.PublicKey) *PullClient {
	return &PullClient{
		policyURL: policyURL,
		verifyKey: verifyKey,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Pull fetches the signed policy config and verifies the signature.
// Returns the verified policy content or an error if the signature
// is invalid or the config has expired.
func (c *PullClient) Pull(ctx context.Context) (*PolicyContent, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.policyURL, nil)
	if err != nil {
		return nil, fmt.Errorf("policy pull: create request: %w", err)
	}
	req.Header.Set("Accept", "application/yaml")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("policy pull: fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("policy pull: server returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if err != nil {
		return nil, fmt.Errorf("policy pull: read body: %w", err)
	}

	var cfg SignedConfig
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("policy pull: parse YAML: %w", err)
	}

	// Verify signature.
	if err := c.verify(&cfg, body); err != nil {
		return nil, err
	}

	// Check expiration.
	if cfg.ExpiresAt != "" {
		expires, parseErr := time.Parse(time.RFC3339, cfg.ExpiresAt)
		if parseErr == nil && time.Now().After(expires) {
			return nil, fmt.Errorf("policy pull: config expired at %s", cfg.ExpiresAt)
		}
	}

	return &cfg.Policy, nil
}

// verify checks the Ed25519 signature of the policy config.
func (c *PullClient) verify(cfg *SignedConfig, rawYAML []byte) error {
	if cfg.Signature == "" {
		return fmt.Errorf("policy pull: missing signature")
	}

	sig, err := base64.StdEncoding.DecodeString(cfg.Signature)
	if err != nil {
		return fmt.Errorf("policy pull: decode signature: %w", err)
	}

	// Reconstruct the signed content (everything except the signature line).
	// We sign the raw bytes for simplicity — the SaaS must produce the
	// signature over the same canonical form.
	signable := signableContent(cfg)
	if !ed25519.Verify(c.verifyKey, signable, sig) {
		return fmt.Errorf("policy pull: signature verification failed")
	}
	return nil
}

// signableContent produces the canonical bytes that are signed.
// This is the YAML-serialised config with the signature field zeroed.
func signableContent(cfg *SignedConfig) []byte {
	copy := *cfg
	copy.Signature = ""
	data, _ := yaml.Marshal(&copy)
	return data
}
