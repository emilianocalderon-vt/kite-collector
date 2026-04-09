package sqlite

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/vulnertrack/kite-collector/internal/store"
)

// EncryptedStore wraps an SQLiteStore with at-rest AES-256-GCM encryption.
// On open, if an encrypted file exists, it is decrypted to a working copy.
// On close, the working copy is encrypted back to disk and the plaintext
// working copy is securely removed.
//
// See RFC-0077 §5.2.4 for the encryption protocol.
type EncryptedStore struct {
	store.Store                  // embedded SQLiteStore
	encPath     string           // path to the encrypted file on disk
	workPath    string           // path to the decrypted working copy
	key         []byte           // AES-256 key (32 bytes)
	logger      *slog.Logger
	keyBackend  string           // "tpm", "keyring", or "file"
}

// NewEncrypted opens an encrypted SQLite database. If encPath contains
// encrypted data, it is decrypted using key. If encPath does not exist,
// a fresh (unencrypted) database is created at the working path and will
// be encrypted on Close.
//
// keyBackend is the identity backend name ("tpm", "keyring", "file")
// and controls whether a security warning is emitted at startup.
func NewEncrypted(encPath string, key []byte, keyBackend string, logger *slog.Logger) (*EncryptedStore, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encrypted store: key must be 32 bytes, got %d", len(key))
	}

	// Emit warning for file-backed keys (RFC-0077 §R3).
	if keyBackend == "file" {
		logger.Warn(
			"SQLite encryption key derived from file-backed identity — "+
				"encryption is ineffective if the key file is on the same disk. "+
				"Use key_backend=tpm or key_backend=keyring for meaningful protection.",
			"key_backend", keyBackend,
		)
	}

	dir := filepath.Dir(encPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("encrypted store: create dir: %w", err)
	}

	// Working copy sits next to the encrypted file.
	workPath := encPath + ".work"

	encrypted, err := IsEncrypted(encPath)
	if err != nil {
		return nil, fmt.Errorf("encrypted store: check encrypted: %w", err)
	}

	if encrypted {
		logger.Info("decrypting database for use", "path", encPath)
		if err := DecryptFile(encPath, workPath, key); err != nil {
			return nil, fmt.Errorf("encrypted store: decrypt: %w", err)
		}
	} else if fileExists(encPath) {
		// Unencrypted existing DB — first time enabling encryption.
		logger.Info("migrating unencrypted database to encrypted storage", "path", encPath)
		if err := copyFile(encPath, workPath); err != nil {
			return nil, fmt.Errorf("encrypted store: copy: %w", err)
		}
	}

	inner, err := New(workPath)
	if err != nil {
		return nil, err
	}

	return &EncryptedStore{
		Store:      inner,
		encPath:    encPath,
		workPath:   workPath,
		key:        key,
		logger:     logger,
		keyBackend: keyBackend,
	}, nil
}

// Close encrypts the working database back to disk, then removes
// the plaintext working copy.
func (es *EncryptedStore) Close() error {
	// Close the inner SQLite connection first.
	if err := es.Store.Close(); err != nil {
		return fmt.Errorf("encrypted store: close inner: %w", err)
	}

	// Encrypt working copy → encrypted file.
	if fileExists(es.workPath) {
		es.logger.Info("encrypting database at rest", "path", es.encPath)
		if err := EncryptFile(es.workPath, es.encPath, es.key); err != nil {
			return fmt.Errorf("encrypted store: encrypt on close: %w", err)
		}

		// Remove plaintext working copy.
		if err := os.Remove(es.workPath); err != nil {
			es.logger.Warn("failed to remove plaintext working copy",
				"path", es.workPath, "error", err)
		}
		// Also remove WAL and SHM files left by SQLite.
		_ = os.Remove(es.workPath + "-wal")
		_ = os.Remove(es.workPath + "-shm")
	}

	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src) // #nosec G304
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0600)
}
