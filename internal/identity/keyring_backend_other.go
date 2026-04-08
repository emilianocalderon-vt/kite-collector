//go:build !linux

package identity

import (
	"crypto"
	"fmt"
)

// KeyringBackend is not available on non-Linux platforms.
type KeyringBackend struct{}

// NewKeyringBackend returns a keyring backend that is always unavailable
// on non-Linux platforms.
func NewKeyringBackend() *KeyringBackend { return &KeyringBackend{} }

func (b *KeyringBackend) Name() string    { return "keyring" }
func (b *KeyringBackend) Available() bool { return false }

func (b *KeyringBackend) Store(_ string, _ crypto.PrivateKey) error {
	return fmt.Errorf("keyring backend: not available on this platform")
}

func (b *KeyringBackend) Load(_ string) (crypto.PrivateKey, error) {
	return nil, fmt.Errorf("keyring backend: not available on this platform")
}
