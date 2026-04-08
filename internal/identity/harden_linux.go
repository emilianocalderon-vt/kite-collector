//go:build linux

package identity

import (
	"log/slog"
	"os"

	"golang.org/x/sys/unix"
)

// HardenProcess applies security hardening on Linux:
// - PR_SET_DUMPABLE=0: prevents core dumps and /proc/pid/mem reads
// - mlockall: locks memory pages to prevent key material hitting swap
func HardenProcess(logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}

	// Prevent core dumps and /proc/pid/mem reads.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		logger.Warn("failed to set PR_SET_DUMPABLE=0", "error", err)
	} else {
		logger.Info("process hardening: core dumps disabled (PR_SET_DUMPABLE=0)")
	}

	// Lock all current and future memory pages (prevent swap).
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		logger.Warn("failed to mlockall — key material may be swapped to disk", "error", err)
	} else {
		logger.Info("process hardening: memory locked (mlockall)")
	}
}

// TPMAvailable checks if a TPM 2.0 device is accessible.
// It attempts to open the device read-write to confirm actual access,
// not just existence (which unix.Stat would report even without permission).
func TPMAvailable() bool {
	for _, path := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err == nil {
			_ = f.Close()
			return true
		}
	}
	return false
}

// KeyringAvailable checks if the Linux kernel keyring is fully usable.
// It probes a store→read→unlink cycle with a disposable test key to
// confirm the kernel security module permits all required operations.
func KeyringAvailable() bool {
	keyring := unix.KEY_SPEC_USER_SESSION_KEYRING
	if _, err := unix.KeyctlGetKeyringID(keyring, false); err != nil {
		return false
	}

	// Probe with a disposable key to verify add, search, read, and unlink.
	const probe = "kite-collector:__probe__"
	payload := []byte("probe")

	id, err := unix.AddKey("user", probe, payload, keyring)
	if err != nil {
		return false
	}
	const keyctlUnlink = 9 // KEYCTL_UNLINK
	defer unix.KeyctlInt(keyctlUnlink, id, keyring, 0, 0) //nolint:errcheck

	found, err := unix.KeyctlSearch(keyring, "user", probe, 0)
	if err != nil || found != id {
		return false
	}

	buf := make([]byte, len(payload))
	n, err := unix.KeyctlBuffer(keyctlRead, id, buf, 0)
	if err != nil || n != len(payload) {
		return false
	}

	return true
}
