package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileBackend_StoreLoad(t *testing.T) {
	dir := t.TempDir()
	backend := NewFileBackend(dir)

	assert.Equal(t, "file", backend.Name())
	assert.True(t, backend.Available())

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	require.NoError(t, backend.Store("test-key", priv))

	loaded, err := backend.Load("test-key")
	require.NoError(t, err)

	loadedKey, ok := loaded.(ed25519.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, priv, loadedKey)
}

func TestFileBackend_LoadMissing(t *testing.T) {
	dir := t.TempDir()
	backend := NewFileBackend(dir)

	_, err := backend.Load("nonexistent")
	assert.Error(t, err)
}

func TestDetectKeyBackend_ReturnsFileByDefault(t *testing.T) {
	dir := t.TempDir()
	backend := DetectKeyBackend("auto", dir, slog.Default())
	assert.Equal(t, "file", backend.Name())
}

func TestDetectKeyBackend_FileExplicit(t *testing.T) {
	dir := t.TempDir()
	backend := DetectKeyBackend("file", dir, slog.Default())
	assert.Equal(t, "file", backend.Name())
}

func TestTPMBackend_Name(t *testing.T) {
	backend := NewTPMBackend(t.TempDir())
	assert.Equal(t, "tpm", backend.Name())
}

func TestTPMBackend_StoreLoad(t *testing.T) {
	if !TPMAvailable() {
		t.Skip("no TPM 2.0 device available")
	}

	dir := t.TempDir()
	backend := NewTPMBackend(dir)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	require.NoError(t, backend.Store("test-key", priv))

	loaded, err := backend.Load("test-key")
	require.NoError(t, err)

	loadedKey, ok := loaded.(ed25519.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, priv, loadedKey)
}

func TestKeyringBackend_Name(t *testing.T) {
	backend := NewKeyringBackend()
	assert.Equal(t, "keyring", backend.Name())
}

func TestKeyringBackend_StoreLoad(t *testing.T) {
	if !KeyringAvailable() {
		t.Skip("kernel keyring not available")
	}

	backend := NewKeyringBackend()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	require.NoError(t, backend.Store("test-key", priv))

	loaded, err := backend.Load("test-key")
	require.NoError(t, err)

	loadedKey, ok := loaded.(ed25519.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, priv, loadedKey)
}

func TestDetectKeyBackend_TPMFallback(t *testing.T) {
	// When TPM is explicitly requested but unavailable, should fall back to file.
	if TPMAvailable() {
		t.Skip("TPM is available — cannot test fallback")
	}
	dir := t.TempDir()
	backend := DetectKeyBackend("tpm", dir, slog.Default())
	assert.Equal(t, "file", backend.Name())
}

func TestDetectKeyBackend_KeyringFallback(t *testing.T) {
	// When keyring is explicitly requested but unavailable, should fall back to file.
	if KeyringAvailable() {
		t.Skip("keyring is available — cannot test fallback")
	}
	dir := t.TempDir()
	backend := DetectKeyBackend("keyring", dir, slog.Default())
	assert.Equal(t, "file", backend.Name())
}

func TestHardenProcess(t *testing.T) {
	// Just verify it doesn't panic. Actual hardening effects
	// depend on platform capabilities and privileges.
	HardenProcess(slog.Default())
}
