package sqlite

import (
	"context"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Embedded FS validation
// ---------------------------------------------------------------------------

func TestMigrationsEmbedded(t *testing.T) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	require.NoError(t, err)

	var sqlFiles int
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			sqlFiles++
		}
	}
	assert.GreaterOrEqual(t, sqlFiles, 1,
		"expected at least one embedded .sql migration")
}

func TestMigrateFilenameConvention(t *testing.T) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	require.NoError(t, err)

	re := regexp.MustCompile(`^\d{3}_`)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		assert.True(t, re.MatchString(e.Name()),
			"migration %q does not match NNN_ convention", e.Name())
	}
}

func TestEmbeddedMigrationCount(t *testing.T) {
	count := EmbeddedMigrationCount()
	assert.GreaterOrEqual(t, count, 1,
		"expected at least one embedded migration")
}

// ---------------------------------------------------------------------------
// Migrate on fresh and existing databases
// ---------------------------------------------------------------------------

func TestMigrate_NewDatabaseAppliesAll(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "new.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Migrate(context.Background()))

	infos, err := s.MigrationStatus(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, infos)

	for _, info := range infos {
		assert.True(t, info.Applied,
			"migration %s should be applied on fresh database", info.Version)
		assert.NotEmpty(t, info.AppliedAt)
		assert.Equal(t, info.Checksum, info.AppliedChecksum,
			"checksum should match for freshly applied %s", info.Version)
	}
}

func TestMigrate_SkipsAlreadyApplied(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "skip.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Migrate(context.Background()))

	// Capture applied_at timestamps from first run.
	before, err := s.MigrationStatus(context.Background())
	require.NoError(t, err)
	timestamps := make(map[string]string, len(before))
	for _, info := range before {
		timestamps[info.Version] = info.AppliedAt
	}

	// Second Migrate must be idempotent — no errors, no re-application.
	require.NoError(t, s.Migrate(context.Background()))

	after, err := s.MigrationStatus(context.Background())
	require.NoError(t, err)
	for _, info := range after {
		assert.True(t, info.Applied)
		assert.Equal(t, timestamps[info.Version], info.AppliedAt,
			"applied_at for %s should not change on re-run", info.Version)
	}
}

// ---------------------------------------------------------------------------
// MigrationStatus
// ---------------------------------------------------------------------------

func TestMigrationStatus_BeforeAndAfterMigrate(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "status.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	// Before migration — all pending.
	infos, err := s.MigrationStatus(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, infos)
	for _, info := range infos {
		assert.False(t, info.Applied,
			"migration %s should be pending before Migrate", info.Version)
	}

	// After migration — all applied.
	require.NoError(t, s.Migrate(context.Background()))
	infos, err = s.MigrationStatus(context.Background())
	require.NoError(t, err)
	for _, info := range infos {
		assert.True(t, info.Applied,
			"migration %s should be applied after Migrate", info.Version)
		assert.NotEmpty(t, info.Checksum)
		assert.NotEmpty(t, info.AppliedChecksum)
	}
}

// ---------------------------------------------------------------------------
// RepairMigration
// ---------------------------------------------------------------------------

func TestRepairMigration_ReAppliesOnNextRun(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "repair.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Migrate(context.Background()))

	// Repair a specific migration.
	require.NoError(t, s.RepairMigration(context.Background(), "002_config_findings"))

	// Status should show it as pending.
	infos, err := s.MigrationStatus(context.Background())
	require.NoError(t, err)
	for _, info := range infos {
		if info.Version == "002_config_findings" {
			assert.False(t, info.Applied,
				"repaired migration should be pending")
		}
	}

	// Re-running Migrate should re-apply it.
	require.NoError(t, s.Migrate(context.Background()))
	infos, err = s.MigrationStatus(context.Background())
	require.NoError(t, err)
	for _, info := range infos {
		assert.True(t, info.Applied,
			"all migrations should be applied after re-migrate")
	}
}

func TestRepairMigration_NotFound(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "repair_nf.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Migrate(context.Background()))

	err = s.RepairMigration(context.Background(), "999_nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// Version tracking
// ---------------------------------------------------------------------------

func TestMigrate_RecordsChecksums(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "checksum.db")
	s, err := New(dbPath)
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Migrate(context.Background()))

	infos, err := s.MigrationStatus(context.Background())
	require.NoError(t, err)
	for _, info := range infos {
		assert.Len(t, info.AppliedChecksum, 64,
			"SHA256 hex should be 64 chars for %s", info.Version)
		assert.Equal(t, info.Checksum, info.AppliedChecksum,
			"embedded and applied checksums must match for %s", info.Version)
	}
}
