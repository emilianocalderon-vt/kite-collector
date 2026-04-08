//go:build linux

package identity

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// TPMBackend stores private keys sealed to the local TPM 2.0 device.
// The sealed data can only be decrypted on this specific TPM, so the
// files on disk ("*.tpm-pub", "*.tpm-priv") are opaque blobs.
type TPMBackend struct {
	dir string
}

// NewTPMBackend creates a TPM-based key backend rooted at dir.
func NewTPMBackend(dir string) *TPMBackend {
	return &TPMBackend{dir: dir}
}

func (b *TPMBackend) Name() string    { return "tpm" }
func (b *TPMBackend) Available() bool { return TPMAvailable() }

func (b *TPMBackend) Store(label string, key crypto.PrivateKey) error {
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("tpm backend: unsupported key type %T", key)
	}

	tpm, err := openTPMDevice()
	if err != nil {
		return fmt.Errorf("open TPM: %w", err)
	}
	defer func() { _ = tpm.Close() }()

	// Create the Storage Root Key (SRK). The SRK is deterministic — the
	// same template on the same TPM always produces the same primary key.
	srk, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("create SRK: %w", err)
	}
	defer func() {
		_, _ = tpm2.FlushContext{FlushHandle: srk.ObjectHandle}.Execute(tpm) // #nosec G104
	}()

	// Seal the Ed25519 private key under the SRK. The sealed blob is
	// bound to this TPM — it cannot be loaded on any other TPM.
	sealedData := &tpm2.TPM2BSensitiveData{Buffer: edKey}
	sealed, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: srk.ObjectHandle,
			Name:   srk.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(sealedData),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
				NoDA:         true,
			},
		}),
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("seal key to TPM: %w", err)
	}

	if err := os.MkdirAll(b.dir, 0700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}

	pubBytes := tpm2.Marshal(sealed.OutPublic)
	privBytes := tpm2.Marshal(sealed.OutPrivate)

	pubPath := filepath.Join(b.dir, label+".tpm-pub")
	privPath := filepath.Join(b.dir, label+".tpm-priv")

	if err := os.WriteFile(pubPath, pubBytes, 0600); err != nil {
		return fmt.Errorf("write sealed pub: %w", err)
	}
	if err := os.WriteFile(privPath, privBytes, 0600); err != nil {
		return fmt.Errorf("write sealed priv: %w", err)
	}

	return nil
}

func (b *TPMBackend) Load(label string) (crypto.PrivateKey, error) {
	tpm, err := openTPMDevice()
	if err != nil {
		return nil, fmt.Errorf("open TPM: %w", err)
	}
	defer func() { _ = tpm.Close() }()

	// Recreate the same SRK to unseal.
	srk, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("create SRK: %w", err)
	}
	defer func() {
		_, _ = tpm2.FlushContext{FlushHandle: srk.ObjectHandle}.Execute(tpm) // #nosec G104
	}()

	pubPath := filepath.Join(b.dir, label+".tpm-pub")
	privPath := filepath.Join(b.dir, label+".tpm-priv")

	pubBytes, err := os.ReadFile(pubPath) // #nosec G304 — path from trusted config
	if err != nil {
		return nil, fmt.Errorf("read sealed pub: %w", err)
	}
	privBytes, err := os.ReadFile(privPath) // #nosec G304 — path from trusted config
	if err != nil {
		return nil, fmt.Errorf("read sealed priv: %w", err)
	}

	outPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal sealed pub: %w", err)
	}
	outPrivate, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal sealed priv: %w", err)
	}

	// Load the sealed object into the TPM.
	loaded, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: srk.ObjectHandle,
			Name:   srk.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic:  *outPublic,
		InPrivate: *outPrivate,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("load sealed object: %w", err)
	}
	defer func() {
		_, _ = tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}.Execute(tpm) // #nosec G104
	}()

	// Unseal to get the raw key bytes.
	unsealed, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("unseal key: %w", err)
	}

	keyBytes := unsealed.OutData.Buffer
	if len(keyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid unsealed key size: got %d, want %d", len(keyBytes), ed25519.PrivateKeySize)
	}

	return ed25519.PrivateKey(keyBytes), nil
}

// openTPMDevice tries the standard Linux TPM device paths in order.
func openTPMDevice() (transport.TPMCloser, error) {
	for _, path := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		tpm, err := linuxtpm.Open(path)
		if err == nil {
			return tpm, nil
		}
	}
	return nil, fmt.Errorf("no accessible TPM device found")
}
