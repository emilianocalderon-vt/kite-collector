package identity

import (
	"crypto/ed25519"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadOrCreate_GeneratesNewIdentity(t *testing.T) {
	dir := t.TempDir()
	logger := slog.Default()

	id, err := LoadOrCreate(dir, logger)
	require.NoError(t, err)
	require.NotNil(t, id)

	assert.NotEqual(t, [16]byte{}, id.AgentID)
	assert.Len(t, id.PublicKey, ed25519.PublicKeySize)
	assert.Len(t, id.PrivateKey, ed25519.PrivateKeySize)

	// File must exist.
	_, err = os.Stat(filepath.Join(dir, "identity.json"))
	require.NoError(t, err)
}

func TestLoadOrCreate_LoadsExistingIdentity(t *testing.T) {
	dir := t.TempDir()
	logger := slog.Default()

	id1, err := LoadOrCreate(dir, logger)
	require.NoError(t, err)

	id2, err := LoadOrCreate(dir, logger)
	require.NoError(t, err)

	assert.Equal(t, id1.AgentID, id2.AgentID)
	assert.Equal(t, id1.PublicKey, id2.PublicKey)
}

func TestIdentity_Fingerprint(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)

	fp := id.Fingerprint()
	assert.Contains(t, fp, "sha256:")
	assert.Len(t, fp, 7+64) // "sha256:" + 64 hex chars
}

func TestIdentity_JSONRoundTrip(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)

	data, err := json.Marshal(id)
	require.NoError(t, err)

	var id2 Identity
	require.NoError(t, json.Unmarshal(data, &id2))

	assert.Equal(t, id.AgentID, id2.AgentID)
	assert.Equal(t, id.PublicKey, id2.PublicKey)
	assert.Equal(t, id.PrivateKey, id2.PrivateKey)
}

func TestLoadOrCreate_RejectsInsecurePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission check not applicable on Windows")
	}

	dir := t.TempDir()
	id, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)

	// Make the file world-readable.
	idPath := filepath.Join(dir, "identity.json")
	require.NoError(t, os.Chmod(idPath, 0644))

	_, err = LoadOrCreate(dir, slog.Default())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insecure permissions")

	// Verify we can still use the originally loaded identity.
	assert.NotNil(t, id)
}

func TestDeriveStorageKey_Returns32Bytes(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)

	key, err := id.DeriveStorageKey()
	require.NoError(t, err)
	assert.Len(t, key, 32, "AES-256 key must be 32 bytes")
}

func TestDeriveStorageKey_Deterministic(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)

	key1, err := id.DeriveStorageKey()
	require.NoError(t, err)

	key2, err := id.DeriveStorageKey()
	require.NoError(t, err)

	assert.Equal(t, key1, key2, "same identity must derive the same key")
}

func TestDeriveStorageKey_DifferentIdentitiesProduceDifferentKeys(t *testing.T) {
	id1, err := LoadOrCreate(t.TempDir(), slog.Default())
	require.NoError(t, err)

	id2, err := LoadOrCreate(t.TempDir(), slog.Default())
	require.NoError(t, err)

	key1, err := id1.DeriveStorageKey()
	require.NoError(t, err)
	key2, err := id2.DeriveStorageKey()
	require.NoError(t, err)

	assert.NotEqual(t, key1, key2, "different identities must derive different keys")
}

func TestDeriveStorageKey_SurvivesReload(t *testing.T) {
	dir := t.TempDir()

	id1, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)
	key1, err := id1.DeriveStorageKey()
	require.NoError(t, err)

	// Reload identity from disk.
	id2, err := LoadOrCreate(dir, slog.Default())
	require.NoError(t, err)
	key2, err := id2.DeriveStorageKey()
	require.NoError(t, err)

	assert.Equal(t, key1, key2, "reloaded identity must derive the same key")
}
