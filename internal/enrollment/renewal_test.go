package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldRenew(t *testing.T) {
	now := time.Now()

	tests := []struct {
		notBefore time.Time
		notAfter  time.Time
		name      string
		want      bool
	}{
		{
			name:      "fresh certificate - no renewal",
			notBefore: now.Add(-1 * time.Hour),
			notAfter:  now.Add(89 * time.Hour), // 90h total, 1h elapsed = 1.1%
			want:      false,
		},
		{
			name:      "past 2/3 lifetime - should renew",
			notBefore: now.Add(-70 * time.Hour),
			notAfter:  now.Add(20 * time.Hour), // 90h total, 70h elapsed = 77%
			want:      true,
		},
		{
			name:      "exactly at 2/3 - should renew",
			notBefore: now.Add(-60 * time.Hour),
			notAfter:  now.Add(30 * time.Hour), // 90h total, 60h = 66.7%
			want:      true,
		},
		{
			name:      "expired - should renew",
			notBefore: now.Add(-100 * time.Hour),
			notAfter:  now.Add(-10 * time.Hour),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldRenew(tt.notBefore, tt.notAfter)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGenerateCSR(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	csrDER, err := generateCSR("test-agent-123", priv)
	require.NoError(t, err)
	require.NotEmpty(t, csrDER)

	// Parse the CSR to verify it's valid.
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)
	assert.Equal(t, "test-agent-123", csr.Subject.CommonName)
	assert.Equal(t, x509.PureEd25519, csr.SignatureAlgorithm)
}

func TestParseCertExpiry(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	notBefore := time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Second)
	notAfter := time.Now().Add(89 * time.Hour).UTC().Truncate(time.Second)

	certDER, err := GenerateSelfSignedCert(priv, pub, notBefore, notAfter)
	require.NoError(t, err)

	nb, na, err := ParseCertExpiry(certDER)
	require.NoError(t, err)

	assert.Equal(t, notBefore, nb)
	assert.Equal(t, notAfter, na)
}
