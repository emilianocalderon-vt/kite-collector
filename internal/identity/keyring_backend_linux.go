//go:build linux

package identity

import (
	"crypto"
	"crypto/ed25519"
	"fmt"

	"golang.org/x/sys/unix"
)

const (
	keyringKeyPrefix = "kite-collector:"
	keyctlRead       = 11 // KEYCTL_READ — read a key's payload
)

// KeyringBackend stores private keys in the Linux kernel's user session
// keyring. Keys exist only in kernel memory and are not written to the
// filesystem. The keyring is per-UID and persists across processes in
// the same session.
type KeyringBackend struct {
	keyring int
}

// NewKeyringBackend creates a kernel keyring backed key backend.
func NewKeyringBackend() *KeyringBackend {
	return &KeyringBackend{
		keyring: unix.KEY_SPEC_USER_SESSION_KEYRING,
	}
}

func (b *KeyringBackend) Name() string    { return "keyring" }
func (b *KeyringBackend) Available() bool { return KeyringAvailable() }

func (b *KeyringBackend) Store(label string, key crypto.PrivateKey) error {
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("keyring backend: unsupported key type %T", key)
	}

	description := keyringKeyPrefix + label
	_, err := unix.AddKey("user", description, edKey, b.keyring)
	if err != nil {
		return fmt.Errorf("add key to keyring: %w", err)
	}
	return nil
}

func (b *KeyringBackend) Load(label string) (crypto.PrivateKey, error) {
	description := keyringKeyPrefix + label

	keyID, err := unix.KeyctlSearch(b.keyring, "user", description, 0)
	if err != nil {
		return nil, fmt.Errorf("key not found in keyring: %w", err)
	}

	buf := make([]byte, ed25519.PrivateKeySize)
	n, err := unix.KeyctlBuffer(keyctlRead, keyID, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("read key from keyring: %w", err)
	}
	if n != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key size from keyring: got %d, want %d", n, ed25519.PrivateKeySize)
	}

	return ed25519.PrivateKey(buf[:n]), nil
}
