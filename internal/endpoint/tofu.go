package endpoint

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

const fingerprintFile = "server-fingerprint.sha256"

// ErrFingerprintMismatch is returned when the server's certificate
// fingerprint does not match the previously pinned value.
var ErrFingerprintMismatch = errors.New("server certificate fingerprint mismatch (possible MITM)")

// CertFingerprint computes the SHA-256 fingerprint of an X.509 certificate.
func CertFingerprint(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

// CheckTOFU verifies the server certificate fingerprint against the stored
// value. On first connection (no stored fingerprint), it pins the current
// certificate. Returns ErrFingerprintMismatch if the fingerprint changed.
func CheckTOFU(credDir string, serverCert *x509.Certificate, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	actual := CertFingerprint(serverCert)
	fpPath := filepath.Join(credDir, fingerprintFile)

	stored, err := os.ReadFile(fpPath) // #nosec G304 — path from trusted config
	if errors.Is(err, fs.ErrNotExist) {
		// First connection — pin this fingerprint.
		if writeErr := os.WriteFile(fpPath, []byte(actual), 0600); writeErr != nil {
			return fmt.Errorf("pin server fingerprint: %w", writeErr)
		}
		logger.Info("TOFU: pinned server certificate fingerprint",
			"fingerprint", actual,
			"path", fpPath,
		)
		return nil
	}
	if err != nil {
		return fmt.Errorf("read stored fingerprint: %w", err)
	}

	expected := strings.TrimSpace(string(stored))
	if actual != expected {
		logger.Error("TOFU: server certificate fingerprint MISMATCH",
			"expected", expected,
			"actual", actual,
		)
		return ErrFingerprintMismatch
	}

	logger.Debug("TOFU: fingerprint verified", "fingerprint", actual)
	return nil
}

// AcceptNewFingerprint replaces the stored fingerprint for the given
// endpoint, acknowledging a legitimate certificate change.
func AcceptNewFingerprint(credDir string, logger *slog.Logger) error {
	fpPath := filepath.Join(credDir, fingerprintFile)

	// Remove the old fingerprint so the next connection re-pins.
	if err := os.Remove(fpPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove old fingerprint: %w", err)
	}

	if logger != nil {
		logger.Info("TOFU: fingerprint reset — next connection will pin new certificate",
			"path", fpPath,
		)
	}
	return nil
}
