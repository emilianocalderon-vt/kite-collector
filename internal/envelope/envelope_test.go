package envelope

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	// Generate agent Ed25519 keypair.
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Generate server ECDH keypair (P-256 for ECDH-ES).
	serverECKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverJWK := jose.JSONWebKey{
		Key:       serverECKey.Public(),
		KeyID:     "server-key-test",
		Algorithm: string(jose.ECDH_ES_A256KW),
		Use:       "enc",
	}
	serverDecryptJWK := jose.JSONWebKey{
		Key:       serverECKey,
		KeyID:     "server-key-test",
		Algorithm: string(jose.ECDH_ES_A256KW),
		Use:       "enc",
	}

	plaintext := []byte(`{"assets":[{"hostname":"web-01","type":"server"}]}`)

	// Encrypt (agent side).
	jweCompact, err := Encrypt(plaintext, agentPriv, serverJWK)
	require.NoError(t, err)
	require.NotEmpty(t, jweCompact)

	// The compact JWE should have 5 dot-separated parts.
	assert.Equal(t, 4, countDots(jweCompact))

	// Decrypt (server side).
	recovered, err := Decrypt(jweCompact, serverDecryptJWK, agentPub)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered)
}

func TestEncrypt_InvalidKey(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Use an invalid JWK (wrong key type).
	badJWK := jose.JSONWebKey{
		Key:   "not-a-key",
		KeyID: "bad",
	}

	_, err = Encrypt([]byte("test"), agentPriv, badJWK)
	assert.Error(t, err)
}

func TestDecrypt_WrongKey(t *testing.T) {
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	serverECKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverJWK := jose.JSONWebKey{
		Key:       serverECKey.Public(),
		KeyID:     "server-key",
		Algorithm: string(jose.ECDH_ES_A256KW),
	}

	jweCompact, err := Encrypt([]byte("secret"), agentPriv, serverJWK)
	require.NoError(t, err)

	// Try decrypting with a different key.
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wrongJWK := jose.JSONWebKey{Key: wrongKey, KeyID: "wrong"}

	_, err = Decrypt(jweCompact, wrongJWK, agentPub)
	assert.Error(t, err)
}

func TestSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	payload := []byte("test payload")
	signed, err := sign(payload, priv)
	require.NoError(t, err)

	verified, err := verify(signed, pub)
	require.NoError(t, err)
	assert.Equal(t, payload, verified)
}

func TestVerify_WrongKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signed, err := sign([]byte("payload"), priv)
	require.NoError(t, err)

	_, err = verify(signed, otherPub)
	assert.Error(t, err)
}

func countDots(s string) int {
	n := 0
	for _, c := range s {
		if c == '.' {
			n++
		}
	}
	return n
}
