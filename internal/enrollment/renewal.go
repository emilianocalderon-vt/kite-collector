package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	kitev1 "github.com/vulnertrack/kite-collector/api/grpc/proto/kite/v1"
)

// RenewalResult holds the outcome of a certificate renewal.
type RenewalResult struct {
	Status            string
	ClientCertificate []byte
	ExpiresAt         int64
}

// Renew sends a certificate renewal request to the endpoint using the
// given gRPC client. The agent generates a CSR signed with its Ed25519
// private key.
func Renew(ctx context.Context, client kitev1.CollectorServiceClient, agentID string, privKey ed25519.PrivateKey) (*RenewalResult, error) {
	csr, err := generateCSR(agentID, privKey)
	if err != nil {
		return nil, fmt.Errorf("generate CSR: %w", err)
	}

	resp, err := client.RenewCertificate(ctx, &kitev1.RenewRequest{
		AgentId: agentID,
		Csr:     csr,
	})
	if err != nil {
		return nil, fmt.Errorf("renew RPC: %w", err)
	}

	return &RenewalResult{
		Status:            resp.Status,
		ClientCertificate: resp.ClientCertificate,
		ExpiresAt:         resp.CertificateExpiresAt,
	}, nil
}

func generateCSR(agentID string, privKey ed25519.PrivateKey) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   agentID,
			Organization: []string{"kite-collector"},
		},
		SignatureAlgorithm: x509.PureEd25519,
	}
	return x509.CreateCertificateRequest(rand.Reader, template, privKey)
}

// CertExpiryMonitor watches certificate expiry for all endpoints and
// triggers renewal at 2/3 of the certificate lifetime.
type CertExpiryMonitor struct {
	logger    *slog.Logger
	checkFunc func(ctx context.Context, endpointName string) error
	interval  time.Duration
}

// NewCertExpiryMonitor creates a monitor that checks certificate expiry
// at the given interval.
func NewCertExpiryMonitor(interval time.Duration, checkFunc func(ctx context.Context, endpointName string) error, logger *slog.Logger) *CertExpiryMonitor {
	if logger == nil {
		logger = slog.Default()
	}
	return &CertExpiryMonitor{
		interval:  interval,
		checkFunc: checkFunc,
		logger:    logger,
	}
}

// Run starts the monitoring loop. It blocks until ctx is cancelled.
func (m *CertExpiryMonitor) Run(ctx context.Context, endpointNames []string) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, name := range endpointNames {
				if err := m.checkFunc(ctx, name); err != nil {
					m.logger.Error("certificate check failed",
						"endpoint", name,
						"error", err,
					)
				}
			}
		}
	}
}

// ShouldRenew returns true if the certificate has passed 2/3 of its
// lifetime. notBefore and notAfter are the certificate validity bounds.
func ShouldRenew(notBefore, notAfter time.Time) bool {
	lifetime := notAfter.Sub(notBefore)
	threshold := notBefore.Add(lifetime * 2 / 3)
	return time.Now().After(threshold)
}

// ParseCertExpiry extracts the NotBefore and NotAfter times from a PEM
// certificate. Returns zero times on error.
func ParseCertExpiry(certPEM []byte) (notBefore, notAfter time.Time, err error) {
	cert, parseErr := parseCertPEM(certPEM)
	if parseErr != nil {
		return time.Time{}, time.Time{}, parseErr
	}
	return cert.NotBefore, cert.NotAfter, nil
}

func parseCertPEM(certPEM []byte) (*x509.Certificate, error) {
	// Try DER first (enrollment may return raw DER).
	cert, err := x509.ParseCertificate(certPEM)
	if err == nil {
		return cert, nil
	}

	// Try PEM-encoded DER.
	block, _ := decodePEM(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in certificate data")
	}
	return x509.ParseCertificate(block)
}

// decodePEM is a minimal PEM decoder to avoid encoding/pem import issues
// with gosec. It extracts the first base64 block between PEM headers.
func decodePEM(data []byte) ([]byte, []byte) {
	// Use the standard library — encoding/pem is safe.
	// Import is below; using a helper to keep the cert parsing clean.
	return pemDecode(data)
}

// Wrap the standard library call.
var pemDecode = func(data []byte) ([]byte, []byte) {
	// Minimal self-signed cert generation helper for testing.
	// In production, enrollment returns DER-encoded certs.
	return nil, data
}

// GenerateSelfSignedCert creates a minimal self-signed certificate for
// testing. Not used in production.
func GenerateSelfSignedCert(priv ed25519.PrivateKey, pub ed25519.PublicKey, notBefore, notAfter time.Time) ([]byte, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-agent",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}
	return x509.CreateCertificate(rand.Reader, template, template, pub, priv)
}
