package safenet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestCACert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestTLSConfig(t *testing.T) {
	t.Run("default uses system CAs with TLS 1.2 minimum", func(t *testing.T) {
		t.Setenv("TEST_INSECURE", "")
		t.Setenv("TEST_CA_CERT", "")

		cfg, err := TLSConfig("TEST_INSECURE", "TEST_CA_CERT")
		require.NoError(t, err)
		assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
		assert.False(t, cfg.InsecureSkipVerify)
		assert.Nil(t, cfg.RootCAs)
	})

	t.Run("insecure mode", func(t *testing.T) {
		t.Setenv("TEST_INSECURE", "true")
		t.Setenv("TEST_CA_CERT", "")

		cfg, err := TLSConfig("TEST_INSECURE", "TEST_CA_CERT")
		require.NoError(t, err)
		assert.True(t, cfg.InsecureSkipVerify)
		assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	})

	t.Run("custom CA cert", func(t *testing.T) {
		certPEM := generateTestCACert(t)
		tmpDir := t.TempDir()
		caPath := filepath.Join(tmpDir, "ca.pem")
		require.NoError(t, os.WriteFile(caPath, certPEM, 0o600))

		t.Setenv("TEST_INSECURE", "")
		t.Setenv("TEST_CA_CERT", caPath)

		cfg, err := TLSConfig("TEST_INSECURE", "TEST_CA_CERT")
		require.NoError(t, err)
		assert.False(t, cfg.InsecureSkipVerify)
		assert.NotNil(t, cfg.RootCAs)
		assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	})

	t.Run("missing CA cert file", func(t *testing.T) {
		t.Setenv("TEST_INSECURE", "")
		t.Setenv("TEST_CA_CERT", "/nonexistent/ca.pem")

		_, err := TLSConfig("TEST_INSECURE", "TEST_CA_CERT")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read CA cert")
	})

	t.Run("invalid PEM in CA cert file", func(t *testing.T) {
		tmpDir := t.TempDir()
		caPath := filepath.Join(tmpDir, "bad.pem")
		require.NoError(t, os.WriteFile(caPath, []byte("not a cert"), 0o600))

		t.Setenv("TEST_INSECURE", "")
		t.Setenv("TEST_CA_CERT", caPath)

		_, err := TLSConfig("TEST_INSECURE", "TEST_CA_CERT")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no valid certificates")
	})

	t.Run("insecure takes precedence over CA cert", func(t *testing.T) {
		certPEM := generateTestCACert(t)
		tmpDir := t.TempDir()
		caPath := filepath.Join(tmpDir, "ca.pem")
		require.NoError(t, os.WriteFile(caPath, certPEM, 0o600))

		t.Setenv("TEST_INSECURE", "true")
		t.Setenv("TEST_CA_CERT", caPath)

		cfg, err := TLSConfig("TEST_INSECURE", "TEST_CA_CERT")
		require.NoError(t, err)
		assert.True(t, cfg.InsecureSkipVerify)
		assert.Nil(t, cfg.RootCAs, "insecure mode should not load CA cert")
	})
}
