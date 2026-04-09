package sqlite

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/vulnertrack/kite-collector/internal/store"
)

// EncryptedStore wraps an SQLiteStore with at-rest AES-256-GCM encryption.
// On open, if an encrypted file exists, it is decrypted to a working copy
// in tmpfs (/dev/shm on Linux). The plaintext database never touches the
// persistent filesystem. On close, the working copy is encrypted back to
// disk and the tmpfs copy is removed.
//
// If tmpfs is unavailable (non-Linux, /dev/shm not mounted), the working
// copy falls back to the same directory as the encrypted file with a
// warning logged.
//
// See RFC-0077 §5.2.4 for the encryption protocol.
type EncryptedStore struct {
	store.Store                  // embedded SQLiteStore
	encPath      string          // path to the encrypted file on disk
	workPath     string          // path to the decrypted working copy
	keyBackend   string          // "tpm", "keyring", or "file"
	logger       *slog.Logger
	key          []byte          // AES-256 key (32 bytes)
	useRAMDisk   bool            // true if working copy is on a RAM-backed filesystem
}

// ramdiskCandidates lists potential RAM-backed directories per OS.
//
//   - Linux:  /dev/shm (tmpfs, almost always mounted)
//   - macOS:  /Volumes/RAMDisk (user must create via diskutil;
//     not present by default)
//   - All OS: the system temp dir as a last resort — not RAM-backed
//     but avoids writing next to the encrypted file
//
// Windows has no standard RAM disk. The fallback writes to os.TempDir()
// which is typically %LOCALAPPDATA%\Temp (on the system drive).
var ramdiskCandidates = ramdiskCandidatesForOS()

func ramdiskCandidatesForOS() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{"/dev/shm", "/run/user/" + fmt.Sprint(os.Getuid())}
	case "darwin":
		// macOS users can create a RAM disk with:
		//   diskutil erasevolume HFS+ RAMDisk $(hdiutil attach -nomount ram://2097152)
		return []string{"/Volumes/RAMDisk"}
	default:
		return nil
	}
}

// ramDirAvailable returns the first writable RAM-backed directory,
// or "" if none is usable.
func ramDirAvailable() string {
	for _, candidate := range ramdiskCandidates {
		info, err := os.Stat(candidate)
		if err != nil || !info.IsDir() {
			continue
		}
		// Test writability.
		f, err := os.CreateTemp(candidate, ".kite-probe-*")
		if err != nil {
			continue
		}
		name := f.Name()
		_ = f.Close()
		_ = os.Remove(name)
		return candidate
	}
	return ""
}

// workingPath chooses where to place the decrypted working copy.
//
// Priority:
//  1. RAM-backed directory (/dev/shm on Linux, /Volumes/RAMDisk on macOS)
//     — plaintext never touches persistent storage.
//  2. OS temp directory (os.TempDir()) — not RAM-backed but separate from
//     the encrypted file's directory, reducing exposure on disk theft.
//  3. Same directory as the encrypted file — worst case, logged as warning.
func workingPath(encPath string, logger *slog.Logger) (path string, onRAMDisk bool) {
	base := filepath.Base(encPath) + ".work"

	// Try RAM-backed directory first.
	if ramDir := ramDirAvailable(); ramDir != "" {
		dir := filepath.Join(ramDir, "kite-collector")
		if err := os.MkdirAll(dir, 0700); err == nil {
			p := filepath.Join(dir, base)
			logger.Info("using RAM-backed directory for decrypted working copy",
				"ramdisk_path", p, "os", runtime.GOOS)
			return p, true
		}
	}

	// Fall back to OS temp directory — not RAM but at least not next to
	// the encrypted file.
	tmpDir := filepath.Join(os.TempDir(), "kite-collector")
	if err := os.MkdirAll(tmpDir, 0700); err == nil {
		p := filepath.Join(tmpDir, base)
		logger.Warn("no RAM-backed directory available — "+
			"using OS temp directory for decrypted working copy; "+
			"plaintext may be on persistent storage during operation",
			"temp_path", p, "os", runtime.GOOS)
		return p, false
	}

	// Last resort: same directory.
	logger.Warn("cannot use temp directory — "+
		"decrypted working copy will be alongside encrypted file; "+
		"plaintext is exposed on persistent storage during operation",
		"fallback_path", encPath+".work", "os", runtime.GOOS)
	return encPath + ".work", false
}

// NewEncrypted opens an encrypted SQLite database. If encPath contains
// encrypted data, it is decrypted using key into a tmpfs working copy.
// If encPath does not exist, a fresh database is created in tmpfs and
// will be encrypted on Close.
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

	workPath, onRAMDisk := workingPath(encPath, logger)

	encrypted, err := IsEncrypted(encPath)
	if err != nil {
		return nil, fmt.Errorf("encrypted store: check encrypted: %w", err)
	}

	if encrypted {
		logger.Info("decrypting database into working copy", "path", encPath)
		err = DecryptFile(encPath, workPath, key)
		if err != nil {
			return nil, fmt.Errorf("encrypted store: decrypt: %w", err)
		}
	} else if fileExists(encPath) {
		// Unencrypted existing DB — first time enabling encryption.
		logger.Info("migrating unencrypted database to encrypted storage", "path", encPath)
		err = copyFile(encPath, workPath)
		if err != nil {
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
		useRAMDisk: onRAMDisk,
	}, nil
}

// Close encrypts the working database back to the persistent path,
// then removes the plaintext working copy from tmpfs (or fallback path).
func (es *EncryptedStore) Close() error {
	// Close the inner SQLite connection first.
	if err := es.Store.Close(); err != nil {
		return fmt.Errorf("encrypted store: close inner: %w", err)
	}

	// Encrypt working copy → encrypted file on persistent storage.
	if fileExists(es.workPath) {
		es.logger.Info("encrypting database at rest", "path", es.encPath)
		if err := EncryptFile(es.workPath, es.encPath, es.key); err != nil {
			return fmt.Errorf("encrypted store: encrypt on close: %w", err)
		}

		// Remove plaintext working copy.
		es.removeWorkingFiles()
	}

	return nil
}

// UseRAMDisk reports whether the working copy is on a RAM-backed filesystem.
func (es *EncryptedStore) UseRAMDisk() bool {
	return es.useRAMDisk
}

// removeWorkingFiles cleans up the plaintext working copy and SQLite
// journal files (WAL, SHM).
func (es *EncryptedStore) removeWorkingFiles() {
	for _, path := range []string{
		es.workPath,
		es.workPath + "-wal",
		es.workPath + "-shm",
	} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			es.logger.Warn("failed to remove working file",
				"path", path, "error", err)
		}
	}
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
	safeDst, err := securePath(dst)
	if err != nil {
		return err
	}
	return os.WriteFile(safeDst, data, 0600) // #nosec G703 -- safeDst validated by securePath
}
