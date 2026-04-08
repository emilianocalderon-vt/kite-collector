package endpoint

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func selfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

func TestCheckTOFU_PinsOnFirstConnection(t *testing.T) {
	dir := t.TempDir()
	cert := selfSignedCert(t)
	logger := slog.Default()

	err := CheckTOFU(dir, cert, logger)
	require.NoError(t, err)

	// Fingerprint file should exist.
	fpPath := filepath.Join(dir, fingerprintFile)
	_, err = os.Stat(fpPath)
	require.NoError(t, err)
}

func TestCheckTOFU_AcceptsSameCert(t *testing.T) {
	dir := t.TempDir()
	cert := selfSignedCert(t)
	logger := slog.Default()

	// Pin.
	require.NoError(t, CheckTOFU(dir, cert, logger))
	// Same cert again.
	require.NoError(t, CheckTOFU(dir, cert, logger))
}

func TestCheckTOFU_RejectsDifferentCert(t *testing.T) {
	dir := t.TempDir()
	cert1 := selfSignedCert(t)
	cert2 := selfSignedCert(t)
	logger := slog.Default()

	// Pin cert1.
	require.NoError(t, CheckTOFU(dir, cert1, logger))

	// cert2 should be rejected.
	err := CheckTOFU(dir, cert2, logger)
	require.ErrorIs(t, err, ErrFingerprintMismatch)
}

func TestAcceptNewFingerprint(t *testing.T) {
	dir := t.TempDir()
	cert1 := selfSignedCert(t)
	cert2 := selfSignedCert(t)
	logger := slog.Default()

	// Pin cert1.
	require.NoError(t, CheckTOFU(dir, cert1, logger))

	// Accept new fingerprint.
	require.NoError(t, AcceptNewFingerprint(dir, logger))

	// cert2 should now be pinned.
	require.NoError(t, CheckTOFU(dir, cert2, logger))
}

func TestCertFingerprint(t *testing.T) {
	cert := selfSignedCert(t)
	fp := CertFingerprint(cert)
	assert.Contains(t, fp, "sha256:")
	assert.Len(t, fp, 7+64)
}
