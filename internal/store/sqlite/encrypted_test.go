package sqlite

import (
	"context"
	"crypto/rand"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// Ensure store import is used.
var _ store.AssetFilter

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

func TestNewEncrypted_FreshDatabase(t *testing.T) {
	dir := t.TempDir()
	encPath := filepath.Join(dir, "kite.db")
	key := testKey(t)

	es, err := NewEncrypted(encPath, key, "tpm", slog.Default())
	require.NoError(t, err)
	require.NotNil(t, es)

	require.NoError(t, es.Migrate(context.Background()))
	require.NoError(t, es.Close())

	// After close, the encrypted file should exist.
	_, err = os.Stat(encPath)
	require.NoError(t, err)

	// Encrypted file should not start with SQLite header.
	encrypted, err := IsEncrypted(encPath)
	require.NoError(t, err)
	assert.True(t, encrypted, "closed database file should be encrypted")

	// Plaintext working copy should be removed (check both tmpfs and fallback).
	assert.False(t, fileExists(es.workPath), "working copy should be removed after close")
}

func TestNewEncrypted_ReopenWithSameKey(t *testing.T) {
	dir := t.TempDir()
	encPath := filepath.Join(dir, "kite.db")
	key := testKey(t)

	// Create, write data, close.
	es, err := NewEncrypted(encPath, key, "keyring", slog.Default())
	require.NoError(t, err)
	require.NoError(t, es.Migrate(context.Background()))

	ctx := context.Background()
	asset := makeTestAsset("test-host", model.AssetTypeServer)
	_, _, err = es.UpsertAssets(ctx, []model.Asset{asset})
	require.NoError(t, err)
	require.NoError(t, es.Close())

	// Reopen with same key — data should survive.
	es2, err := NewEncrypted(encPath, key, "keyring", slog.Default())
	require.NoError(t, err)

	assets, err := es2.ListAssets(ctx, store.AssetFilter{})
	require.NoError(t, err)
	assert.Len(t, assets, 1)
	assert.Equal(t, "test-host", assets[0].Hostname)

	require.NoError(t, es2.Close())
}

func TestNewEncrypted_ReopenWithWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	encPath := filepath.Join(dir, "kite.db")
	key1 := testKey(t)
	key2 := testKey(t)

	// Create and close with key1.
	es, err := NewEncrypted(encPath, key1, "tpm", slog.Default())
	require.NoError(t, err)
	require.NoError(t, es.Migrate(context.Background()))
	require.NoError(t, es.Close())

	// Reopen with key2 — should fail.
	_, err = NewEncrypted(encPath, key2, "tpm", slog.Default())
	require.Error(t, err, "opening with wrong key must fail")
	assert.Contains(t, err.Error(), "decrypt")
}

func TestNewEncrypted_RejectsInvalidKeyLength(t *testing.T) {
	dir := t.TempDir()
	encPath := filepath.Join(dir, "kite.db")

	_, err := NewEncrypted(encPath, []byte("too-short"), "tpm", slog.Default())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

func TestNewEncrypted_MigratesUnencryptedDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "kite.db")
	key := testKey(t)

	// Create a plain unencrypted SQLite database first.
	plain, err := New(dbPath)
	require.NoError(t, err)
	require.NoError(t, plain.Migrate(context.Background()))

	ctx := context.Background()
	asset := makeTestAsset("pre-existing", model.AssetTypeWorkstation)
	_, _, err = plain.UpsertAssets(ctx, []model.Asset{asset})
	require.NoError(t, err)
	require.NoError(t, plain.Close())

	// Confirm it's unencrypted.
	encrypted, err := IsEncrypted(dbPath)
	require.NoError(t, err)
	assert.False(t, encrypted)

	// Open with encryption — should migrate automatically.
	es, err := NewEncrypted(dbPath, key, "keyring", slog.Default())
	require.NoError(t, err)

	assets, err := es.ListAssets(ctx, store.AssetFilter{})
	require.NoError(t, err)
	assert.Len(t, assets, 1)
	assert.Equal(t, "pre-existing", assets[0].Hostname)

	require.NoError(t, es.Close())

	// After close, the file should now be encrypted.
	encrypted, err = IsEncrypted(dbPath)
	require.NoError(t, err)
	assert.True(t, encrypted)
}

func TestNewEncrypted_MultipleWriteCloseCycles(t *testing.T) {
	dir := t.TempDir()
	encPath := filepath.Join(dir, "kite.db")
	key := testKey(t)
	ctx := context.Background()

	// Cycle 1: create + write.
	es, err := NewEncrypted(encPath, key, "tpm", slog.Default())
	require.NoError(t, err)
	require.NoError(t, es.Migrate(ctx))
	asset1 := makeTestAsset("host-1", model.AssetTypeServer)
	_, _, err = es.UpsertAssets(ctx, []model.Asset{asset1})
	require.NoError(t, err)
	require.NoError(t, es.Close())

	// Cycle 2: reopen + write more.
	es, err = NewEncrypted(encPath, key, "tpm", slog.Default())
	require.NoError(t, err)
	asset2 := makeTestAsset("host-2", model.AssetTypeContainer)
	_, _, err = es.UpsertAssets(ctx, []model.Asset{asset2})
	require.NoError(t, err)
	require.NoError(t, es.Close())

	// Cycle 3: reopen + verify both assets present.
	es, err = NewEncrypted(encPath, key, "tpm", slog.Default())
	require.NoError(t, err)
	assets, err := es.ListAssets(ctx, store.AssetFilter{})
	require.NoError(t, err)
	assert.Len(t, assets, 2)
	require.NoError(t, es.Close())
}

func TestNewEncrypted_FileBackendWarnsButWorks(t *testing.T) {
	dir := t.TempDir()
	encPath := filepath.Join(dir, "kite.db")
	key := testKey(t)

	// file backend should work — just emits a warning.
	es, err := NewEncrypted(encPath, key, "file", slog.Default())
	require.NoError(t, err)
	require.NoError(t, es.Migrate(context.Background()))
	require.NoError(t, es.Close())
}

func TestNewEncrypted_WorkingCopyOnRAMDisk(t *testing.T) {
	if ramDirAvailable() == "" {
		t.Skip("no RAM-backed directory available")
	}

	dir := t.TempDir()
	encPath := filepath.Join(dir, "kite.db")
	key := testKey(t)

	es, err := NewEncrypted(encPath, key, "tpm", slog.Default())
	require.NoError(t, err)
	require.NoError(t, es.Migrate(context.Background()))

	assert.True(t, es.UseRAMDisk(), "working copy should be on RAM disk")

	// Working copy must NOT be in the same directory as the encrypted file.
	assert.NotEqual(t, filepath.Dir(es.workPath), filepath.Dir(encPath),
		"working copy should not be alongside encrypted file")

	// Working copy must exist while open.
	assert.True(t, fileExists(es.workPath),
		"working copy should exist on RAM disk during operation")

	require.NoError(t, es.Close())

	// After close: RAM disk copy removed, persistent file encrypted.
	assert.False(t, fileExists(es.workPath),
		"RAM disk working copy should be removed after close")
	encrypted, err := IsEncrypted(encPath)
	require.NoError(t, err)
	assert.True(t, encrypted)
}

func TestNewEncrypted_NoPersistentPlaintextDuringOperation(t *testing.T) {
	if ramDirAvailable() == "" {
		t.Skip("no RAM-backed directory available")
	}

	dir := t.TempDir()
	encPath := filepath.Join(dir, "kite.db")
	key := testKey(t)

	es, err := NewEncrypted(encPath, key, "tpm", slog.Default())
	require.NoError(t, err)
	require.NoError(t, es.Migrate(context.Background()))

	ctx := context.Background()
	asset := makeTestAsset("sensitive-host", model.AssetTypeServer)
	_, _, err = es.UpsertAssets(ctx, []model.Asset{asset})
	require.NoError(t, err)

	// When RAM disk is active, no .work files should exist on persistent storage.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if strings.HasSuffix(e.Name(), ".work") ||
			strings.HasSuffix(e.Name(), ".work-wal") ||
			strings.HasSuffix(e.Name(), ".work-shm") {
			t.Errorf("plaintext working file %q on persistent disk while RAM disk is active", p)
		}
	}

	require.NoError(t, es.Close())
}

func TestRAMDirAvailable(t *testing.T) {
	// Just verify it returns without panicking on any OS.
	result := ramDirAvailable()
	if runtime.GOOS == "linux" {
		// On Linux with /dev/shm, should typically find one.
		if _, err := os.Stat("/dev/shm"); err == nil {
			assert.NotEmpty(t, result, "Linux with /dev/shm should detect RAM dir")
		}
	}
	t.Logf("ramDirAvailable() = %q (os=%s)", result, runtime.GOOS)
}

// makeTestAsset creates a minimal asset for testing.
func makeTestAsset(hostname string, assetType model.AssetType) model.Asset {
	now := time.Now().UTC().Truncate(time.Second)
	a := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        hostname,
		AssetType:       assetType,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		DiscoverySource: "test",
		FirstSeenAt:     now,
		LastSeenAt:      now,
	}
	a.ComputeNaturalKey()
	return a
}
