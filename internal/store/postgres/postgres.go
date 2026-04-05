// Package postgres provides a PostgreSQL-backed implementation of store.Store.
// This is a Phase 3 stub: every method returns a "not yet implemented" error
// or sensible zero values. The real implementation will use database/sql with
// the pgx driver once the migration to a shared PostgreSQL backend is complete.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// errNotImplemented is the sentinel error returned by all stub methods.
var errNotImplemented = fmt.Errorf("postgres store not yet implemented")

// PostgresStore implements store.Store against a PostgreSQL database.
// All methods currently return errNotImplemented.
type PostgresStore struct {
	dsn string
}

// Compile-time interface check.
var _ store.Store = (*PostgresStore)(nil)

// New creates a PostgresStore configured with the given DSN. No connection is
// established until Migrate or another method is called.
func New(dsn string) *PostgresStore {
	return &PostgresStore{dsn: dsn}
}

// UpsertAsset inserts or updates a single asset.
func (s *PostgresStore) UpsertAsset(_ context.Context, _ model.Asset) error {
	return errNotImplemented
}

// UpsertAssets inserts or updates a batch of assets in a single transaction.
func (s *PostgresStore) UpsertAssets(_ context.Context, _ []model.Asset) (inserted, updated int, err error) {
	return 0, 0, errNotImplemented
}

// GetAssetByNaturalKey retrieves an asset by its SHA-256 natural key.
func (s *PostgresStore) GetAssetByNaturalKey(_ context.Context, _ string) (*model.Asset, error) {
	return nil, errNotImplemented
}

// ListAssets returns assets matching the supplied filter.
func (s *PostgresStore) ListAssets(_ context.Context, _ store.AssetFilter) ([]model.Asset, error) {
	return nil, errNotImplemented
}

// GetStaleAssets returns assets whose last_seen_at is older than the threshold.
func (s *PostgresStore) GetStaleAssets(_ context.Context, _ time.Duration) ([]model.Asset, error) {
	return nil, errNotImplemented
}

// InsertEvent persists a single asset lifecycle event.
func (s *PostgresStore) InsertEvent(_ context.Context, _ model.AssetEvent) error {
	return errNotImplemented
}

// InsertEvents persists a batch of asset lifecycle events.
func (s *PostgresStore) InsertEvents(_ context.Context, _ []model.AssetEvent) error {
	return errNotImplemented
}

// ListEvents returns events matching the supplied filter.
func (s *PostgresStore) ListEvents(_ context.Context, _ store.EventFilter) ([]model.AssetEvent, error) {
	return nil, errNotImplemented
}

// CreateScanRun records a new scan run.
func (s *PostgresStore) CreateScanRun(_ context.Context, _ model.ScanRun) error {
	return errNotImplemented
}

// CompleteScanRun marks a scan run as completed with the given result.
func (s *PostgresStore) CompleteScanRun(_ context.Context, _ uuid.UUID, _ model.ScanResult) error {
	return errNotImplemented
}

// GetLatestScanRun returns the most recent scan run, or nil if none exist.
func (s *PostgresStore) GetLatestScanRun(_ context.Context) (*model.ScanRun, error) {
	return nil, errNotImplemented
}

// UpsertSoftware replaces all installed software records for the given asset.
func (s *PostgresStore) UpsertSoftware(_ context.Context, _ uuid.UUID, _ []model.InstalledSoftware) error {
	return errNotImplemented
}

// ListSoftware returns all installed software records for the given asset.
func (s *PostgresStore) ListSoftware(_ context.Context, _ uuid.UUID) ([]model.InstalledSoftware, error) {
	return nil, errNotImplemented
}

// Migrate creates the schema tables and indexes if they do not exist.
func (s *PostgresStore) Migrate(_ context.Context) error {
	return errNotImplemented
}

// Close releases all resources held by the store.
func (s *PostgresStore) Close() error {
	return nil
}
