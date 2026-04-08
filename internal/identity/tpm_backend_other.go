//go:build !linux

package identity

import (
	"crypto"
	"fmt"
)

// TPMBackend is not available on non-Linux platforms.
type TPMBackend struct{}

// NewTPMBackend returns a TPM backend that is always unavailable on
// non-Linux platforms.
func NewTPMBackend(_ string) *TPMBackend { return &TPMBackend{} }

func (b *TPMBackend) Name() string    { return "tpm" }
func (b *TPMBackend) Available() bool { return false }

func (b *TPMBackend) Store(_ string, _ crypto.PrivateKey) error {
	return fmt.Errorf("tpm backend: not available on this platform")
}

func (b *TPMBackend) Load(_ string) (crypto.PrivateKey, error) {
	return nil, fmt.Errorf("tpm backend: not available on this platform")
}
