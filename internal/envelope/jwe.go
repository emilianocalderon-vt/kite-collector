// Package envelope provides JWE encryption/decryption and JWS signing/
// verification for end-to-end payload protection beyond mTLS.
package envelope

import (
	"crypto/ed25519"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// Encrypt encrypts plaintext to the server's public JWK using JWE
// (ECDH-ES+A256KW key agreement, A256GCM content encryption) after
// signing with the agent's Ed25519 key via JWS (EdDSA).
func Encrypt(plaintext []byte, agentKey ed25519.PrivateKey, serverJWK jose.JSONWebKey) (string, error) {
	// 1. Sign the payload with the agent's Ed25519 key.
	signed, err := sign(plaintext, agentKey)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	// 2. Encrypt the signed payload to the server's key.
	encrypted, err := encrypt([]byte(signed), serverJWK)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}

	return encrypted, nil
}

// Decrypt decrypts a JWE compact serialization and verifies the inner
// JWS signature. Returns the original plaintext.
func Decrypt(jweCompact string, serverKey jose.JSONWebKey, agentPubKey ed25519.PublicKey) ([]byte, error) {
	// 1. Decrypt the JWE.
	signed, err := decrypt(jweCompact, serverKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	// 2. Verify the JWS signature.
	plaintext, err := verify(string(signed), agentPubKey)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}

	return plaintext, nil
}

func sign(payload []byte, key ed25519.PrivateKey) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: key},
		(&jose.SignerOptions{}).WithType("JWS"),
	)
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign payload: %w", err)
	}

	return jws.CompactSerialize()
}

func encrypt(plaintext []byte, serverJWK jose.JSONWebKey) (string, error) {
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.ECDH_ES_A256KW, Key: serverJWK},
		(&jose.EncrypterOptions{}).WithType("JWE"),
	)
	if err != nil {
		return "", fmt.Errorf("create encrypter: %w", err)
	}

	jwe, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt payload: %w", err)
	}

	return jwe.CompactSerialize()
}

func decrypt(jweCompact string, serverKey jose.JSONWebKey) ([]byte, error) {
	jwe, err := jose.ParseEncrypted(jweCompact, []jose.KeyAlgorithm{jose.ECDH_ES_A256KW}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, fmt.Errorf("parse JWE: %w", err)
	}

	plaintext, err := jwe.Decrypt(serverKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt JWE: %w", err)
	}

	return plaintext, nil
}

func verify(jwsCompact string, pubKey ed25519.PublicKey) ([]byte, error) {
	jws, err := jose.ParseSigned(jwsCompact, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return nil, fmt.Errorf("parse JWS: %w", err)
	}

	payload, err := jws.Verify(pubKey)
	if err != nil {
		return nil, fmt.Errorf("verify JWS: %w", err)
	}

	return payload, nil
}
