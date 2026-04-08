package identity

import "log/slog"

// DetectKeyBackend selects the best available key backend based on the
// requested preference. Detection order for "auto":
// 1. TPM 2.0 (hardware-bound, non-exportable)
// 2. OS keyring (kernel memory, not on filesystem)
// 3. File (fallback, mode 0600)
func DetectKeyBackend(preference, dataDir string, logger *slog.Logger) KeyBackend {
	if logger == nil {
		logger = slog.Default()
	}

	switch preference {
	case "tpm":
		b := NewTPMBackend(dataDir)
		if b.Available() {
			logger.Info("key backend: TPM 2.0 (requested)")
			return b
		}
		logger.Warn("TPM requested but not available, falling back to file")
		return NewFileBackend(dataDir)

	case "keyring":
		b := NewKeyringBackend()
		if b.Available() {
			logger.Info("key backend: OS keyring (requested)")
			return b
		}
		logger.Warn("keyring requested but not available, falling back to file")
		return NewFileBackend(dataDir)

	case "file":
		logger.Info("key backend: file (requested)")
		return NewFileBackend(dataDir)

	default: // "auto" or empty
		if tpm := NewTPMBackend(dataDir); tpm.Available() {
			logger.Info("key backend: TPM 2.0 (auto-detected)")
			return tpm
		}
		if kr := NewKeyringBackend(); kr.Available() {
			logger.Info("key backend: OS keyring (auto-detected)")
			return kr
		}
		logger.Info("key backend: file (fallback)")
		return NewFileBackend(dataDir)
	}
}
