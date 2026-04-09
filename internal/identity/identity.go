// Package identity manages the agent's persistent cryptographic identity.
// On first boot, it generates an Ed25519 keypair and a UUID v7 agent ID,
// persisting them to an identity.json file in the configured data directory.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

// Identity holds the agent's persistent cryptographic identity.
type Identity struct {
	PubKeyB64  string             `json:"public_key"`
	PrivKeyB64 string             `json:"private_key"`
	PublicKey  ed25519.PublicKey  `json:"-"`
	PrivateKey ed25519.PrivateKey `json:"-"`
	AgentID    uuid.UUID          `json:"agent_id"`
}

// MarshalJSON produces the on-disk JSON representation with base64-encoded keys.
func (id *Identity) MarshalJSON() ([]byte, error) {
	type alias struct {
		PublicKey  string    `json:"public_key"`
		PrivateKey string    `json:"private_key"`
		AgentID    uuid.UUID `json:"agent_id"`
	}
	return json.Marshal(alias{
		AgentID:    id.AgentID,
		PublicKey:  base64.StdEncoding.EncodeToString(id.PublicKey),
		PrivateKey: base64.StdEncoding.EncodeToString(id.PrivateKey),
	})
}

// UnmarshalJSON restores an Identity from its on-disk JSON representation.
func (id *Identity) UnmarshalJSON(data []byte) error {
	type alias struct {
		PublicKey  string    `json:"public_key"`
		PrivateKey string    `json:"private_key"`
		AgentID    uuid.UUID `json:"agent_id"`
	}
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(a.PublicKey)
	if err != nil {
		return fmt.Errorf("decode public_key: %w", err)
	}
	priv, err := base64.StdEncoding.DecodeString(a.PrivateKey)
	if err != nil {
		return fmt.Errorf("decode private_key: %w", err)
	}
	id.AgentID = a.AgentID
	id.PublicKey = ed25519.PublicKey(pub)
	id.PrivateKey = ed25519.PrivateKey(priv)
	id.PubKeyB64 = a.PublicKey
	id.PrivKeyB64 = a.PrivateKey
	return nil
}

// Fingerprint returns the SHA-256 fingerprint of the agent's public key.
func (id *Identity) Fingerprint() string {
	h := sha256.Sum256(id.PublicKey)
	return fmt.Sprintf("sha256:%x", h)
}

// DeriveStorageKey derives a 32-byte AES-256 key for SQLite encryption
// using HKDF-SHA256 with the agent's Ed25519 private key as input keying
// material. The salt and info strings provide domain separation so the
// same private key cannot produce identical keys for different purposes.
//
// See RFC-0077 §5.2.4 and §8 Task 1.6.
func (id *Identity) DeriveStorageKey() ([]byte, error) {
	salt := []byte("kite-storage-v1")
	info := []byte("sqlite-encryption")

	hkdfReader := hkdf.New(sha256.New, id.PrivateKey.Seed(), salt, info)
	key := make([]byte, 32) // AES-256
	if _, err := hkdfReader.Read(key); err != nil {
		return nil, fmt.Errorf("derive storage key: %w", err)
	}
	return key, nil
}

// LoadOrCreate loads an existing identity from dataDir/identity.json, or
// generates a new one if the file does not exist. The data directory and
// file are created with restrictive permissions.
func LoadOrCreate(dataDir string, logger *slog.Logger) (*Identity, error) {
	if logger == nil {
		logger = slog.Default()
	}

	idPath := filepath.Join(dataDir, "identity.json")

	// Ensure data directory exists with restricted permissions.
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create identity data dir: %w", err)
	}

	data, err := os.ReadFile(idPath) // #nosec G304 — path derived from trusted config
	if err == nil {
		return loadFromBytes(data, idPath, logger)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read identity file: %w", err)
	}

	// First boot: generate new identity.
	return generate(idPath, logger)
}

func loadFromBytes(data []byte, path string, logger *slog.Logger) (*Identity, error) {
	// Check file permissions on Unix systems.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat identity file: %w", err)
		}
		perm := info.Mode().Perm()
		if perm&0077 != 0 {
			return nil, fmt.Errorf(
				"identity file %s has insecure permissions %04o; expected 0600",
				path, perm,
			)
		}
	}

	var id Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, fmt.Errorf("parse identity file: %w", err)
	}
	if len(id.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: got %d, want %d", len(id.PublicKey), ed25519.PublicKeySize)
	}
	if len(id.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: got %d, want %d", len(id.PrivateKey), ed25519.PrivateKeySize)
	}
	logger.Info("loaded agent identity", "agent_id", id.AgentID, "fingerprint", id.Fingerprint())
	return &id, nil
}

func generate(path string, logger *slog.Logger) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Ed25519 keypair: %w", err)
	}

	id := &Identity{
		AgentID:    uuid.Must(uuid.NewV7()),
		PublicKey:  pub,
		PrivateKey: priv,
	}

	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal identity: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, fmt.Errorf("write identity file: %w", err)
	}

	logger.Info("generated new agent identity",
		"agent_id", id.AgentID,
		"fingerprint", id.Fingerprint(),
		"path", path,
	)
	return id, nil
}
