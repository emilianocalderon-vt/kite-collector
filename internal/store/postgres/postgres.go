// Package postgres provides a PostgreSQL-backed implementation of store.Store
// using pgx/v5 with connection pooling. It is safe for concurrent use and works
// with CGO_ENABLED=0 (pgx is pure Go).
package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// PostgresStore implements store.Store against a PostgreSQL database using a
// pgxpool connection pool. All methods are safe for concurrent use.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// Compile-time interface check.
var _ store.Store = (*PostgresStore)(nil)

// New creates a PostgresStore by parsing the DSN and establishing a connection
// pool. The pool verifies connectivity lazily on first use.
func New(dsn string) (*PostgresStore, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres parse config: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("postgres new pool: %w", err)
	}

	return &PostgresStore{pool: pool}, nil
}

// Migrate creates the schema tables and indexes if they do not already exist.
func (s *PostgresStore) Migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, schema)
	if err != nil {
		return fmt.Errorf("postgres migrate: %w", err)
	}
	return nil
}

// Close releases all connections held by the pool.
func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------

const assetColumns = `id, asset_type, hostname, os_family, os_version,
	is_authorized, is_managed, environment, owner, criticality,
	discovery_source, first_seen_at, last_seen_at, tags, natural_key`

// scanAsset reads a single row into a model.Asset. The column order must match
// assetColumns exactly.
func scanAsset(row pgx.Row) (*model.Asset, error) {
	var a model.Asset
	var (
		osFamily    *string
		osVersion   *string
		environment *string
		owner       *string
		criticality *string
		tags        *string
		naturalKey  *string
	)
	err := row.Scan(
		&a.ID,
		&a.AssetType,
		&a.Hostname,
		&osFamily,
		&osVersion,
		&a.IsAuthorized,
		&a.IsManaged,
		&environment,
		&owner,
		&criticality,
		&a.DiscoverySource,
		&a.FirstSeenAt,
		&a.LastSeenAt,
		&tags,
		&naturalKey,
	)
	if err != nil {
		return nil, err
	}

	a.OSFamily = derefStr(osFamily)
	a.OSVersion = derefStr(osVersion)
	a.Environment = derefStr(environment)
	a.Owner = derefStr(owner)
	a.Criticality = derefStr(criticality)
	a.Tags = derefStr(tags)
	a.NaturalKey = derefStr(naturalKey)

	return &a, nil
}

// scanAssets collects all rows from a pgx.Rows result set into a slice.
func scanAssets(rows pgx.Rows) ([]model.Asset, error) {
	defer rows.Close()
	var assets []model.Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, fmt.Errorf("scan asset row: %w", err)
		}
		assets = append(assets, *a)
	}
	return assets, rows.Err()
}

// UpsertAsset inserts a new asset or updates an existing one matched by the
// UNIQUE(hostname, asset_type) constraint. The natural key is computed before
// writing.
func (s *PostgresStore) UpsertAsset(ctx context.Context, asset model.Asset) error {
	asset.ComputeNaturalKey()

	_, err := s.pool.Exec(ctx, `
		INSERT INTO assets (`+assetColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT(hostname, asset_type) DO UPDATE SET
			os_family        = EXCLUDED.os_family,
			os_version       = EXCLUDED.os_version,
			is_authorized    = EXCLUDED.is_authorized,
			is_managed       = EXCLUDED.is_managed,
			environment      = EXCLUDED.environment,
			owner            = EXCLUDED.owner,
			criticality      = EXCLUDED.criticality,
			discovery_source = EXCLUDED.discovery_source,
			last_seen_at     = EXCLUDED.last_seen_at,
			tags             = EXCLUDED.tags,
			natural_key      = EXCLUDED.natural_key
	`,
		asset.ID,
		string(asset.AssetType),
		asset.Hostname,
		nullStr(asset.OSFamily),
		nullStr(asset.OSVersion),
		string(asset.IsAuthorized),
		string(asset.IsManaged),
		nullStr(asset.Environment),
		nullStr(asset.Owner),
		nullStr(asset.Criticality),
		asset.DiscoverySource,
		asset.FirstSeenAt,
		asset.LastSeenAt,
		nullStr(asset.Tags),
		asset.NaturalKey,
	)
	if err != nil {
		return fmt.Errorf("upsert asset %s: %w", asset.ID, err)
	}
	return nil
}

// UpsertAssets atomically upserts a batch of assets inside a single
// transaction and returns counts of newly inserted and updated rows.
// It uses the PostgreSQL xmax system column trick: after an INSERT ON CONFLICT
// DO UPDATE, xmax = 0 means the row was inserted; xmax != 0 means it was
// updated.
func (s *PostgresStore) UpsertAssets(ctx context.Context, assets []model.Asset) (inserted, updated int, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	for i := range assets {
		assets[i].ComputeNaturalKey()

		var xmax uint32
		err = tx.QueryRow(ctx, `
			INSERT INTO assets (`+assetColumns+`)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
			ON CONFLICT(hostname, asset_type) DO UPDATE SET
				os_family        = EXCLUDED.os_family,
				os_version       = EXCLUDED.os_version,
				is_authorized    = EXCLUDED.is_authorized,
				is_managed       = EXCLUDED.is_managed,
				environment      = EXCLUDED.environment,
				owner            = EXCLUDED.owner,
				criticality      = EXCLUDED.criticality,
				discovery_source = EXCLUDED.discovery_source,
				last_seen_at     = EXCLUDED.last_seen_at,
				tags             = EXCLUDED.tags,
				natural_key      = EXCLUDED.natural_key
			RETURNING xmax
		`,
			assets[i].ID,
			string(assets[i].AssetType),
			assets[i].Hostname,
			nullStr(assets[i].OSFamily),
			nullStr(assets[i].OSVersion),
			string(assets[i].IsAuthorized),
			string(assets[i].IsManaged),
			nullStr(assets[i].Environment),
			nullStr(assets[i].Owner),
			nullStr(assets[i].Criticality),
			assets[i].DiscoverySource,
			assets[i].FirstSeenAt,
			assets[i].LastSeenAt,
			nullStr(assets[i].Tags),
			assets[i].NaturalKey,
		).Scan(&xmax)
		if err != nil {
			return 0, 0, fmt.Errorf("upsert asset %s: %w", assets[i].ID, err)
		}

		if xmax == 0 {
			inserted++
		} else {
			updated++
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, 0, fmt.Errorf("commit tx: %w", err)
	}
	return inserted, updated, nil
}

// GetAssetByNaturalKey retrieves the asset whose precomputed SHA-256 natural
// key matches key. Returns (nil, nil) when no match is found.
func (s *PostgresStore) GetAssetByNaturalKey(ctx context.Context, key string) (*model.Asset, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+assetColumns+` FROM assets WHERE natural_key = $1`, key)
	a, err := scanAsset(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get asset by natural key: %w", err)
	}
	return a, nil
}

// ListAssets returns assets matching the supplied filter. An empty filter
// returns all assets (subject to Limit/Offset).
func (s *PostgresStore) ListAssets(ctx context.Context, filter store.AssetFilter) ([]model.Asset, error) {
	var (
		clauses []string
		args    []any
		paramN  int // positional parameter counter
	)

	if filter.AssetType != "" {
		paramN++
		clauses = append(clauses, fmt.Sprintf("asset_type = $%d", paramN))
		args = append(args, filter.AssetType)
	}
	if filter.IsAuthorized != "" {
		paramN++
		clauses = append(clauses, fmt.Sprintf("is_authorized = $%d", paramN))
		args = append(args, filter.IsAuthorized)
	}
	if filter.IsManaged != "" {
		paramN++
		clauses = append(clauses, fmt.Sprintf("is_managed = $%d", paramN))
		args = append(args, filter.IsManaged)
	}
	if filter.Hostname != "" {
		paramN++
		clauses = append(clauses, fmt.Sprintf("hostname = $%d", paramN))
		args = append(args, filter.Hostname)
	}

	query := `SELECT ` + assetColumns + ` FROM assets`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY last_seen_at DESC"

	if filter.Limit > 0 {
		paramN++
		query += fmt.Sprintf(" LIMIT $%d", paramN)
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		paramN++
		query += fmt.Sprintf(" OFFSET $%d", paramN)
		args = append(args, filter.Offset)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	return scanAssets(rows)
}

// GetStaleAssets returns assets whose last_seen_at is older than the given
// threshold measured from the current time.
func (s *PostgresStore) GetStaleAssets(ctx context.Context, threshold time.Duration) ([]model.Asset, error) {
	cutoff := time.Now().UTC().Add(-threshold)
	rows, err := s.pool.Query(ctx,
		`SELECT `+assetColumns+` FROM assets WHERE last_seen_at < $1 ORDER BY last_seen_at ASC`,
		cutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("get stale assets: %w", err)
	}
	return scanAssets(rows)
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

const eventColumns = `id, event_type, asset_id, scan_run_id, severity, details, timestamp`

// scanEvent reads a single row into a model.AssetEvent. The column order must
// match eventColumns exactly.
func scanEvent(row pgx.Row) (*model.AssetEvent, error) {
	var e model.AssetEvent
	var details *string
	err := row.Scan(
		&e.ID,
		&e.EventType,
		&e.AssetID,
		&e.ScanRunID,
		&e.Severity,
		&details,
		&e.Timestamp,
	)
	if err != nil {
		return nil, err
	}
	e.Details = derefStr(details)
	return &e, nil
}

// scanEvents collects all rows from a pgx.Rows result set into a slice.
func scanEvents(rows pgx.Rows) ([]model.AssetEvent, error) {
	defer rows.Close()
	var events []model.AssetEvent
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("scan event row: %w", err)
		}
		events = append(events, *e)
	}
	return events, rows.Err()
}

// InsertEvent persists a single asset lifecycle event.
func (s *PostgresStore) InsertEvent(ctx context.Context, event model.AssetEvent) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO events (`+eventColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		event.ID,
		string(event.EventType),
		event.AssetID,
		event.ScanRunID,
		string(event.Severity),
		nullStr(event.Details),
		event.Timestamp,
	)
	if err != nil {
		return fmt.Errorf("insert event %s: %w", event.ID, err)
	}
	return nil
}

// InsertEvents persists a batch of events inside a single transaction.
func (s *PostgresStore) InsertEvents(ctx context.Context, events []model.AssetEvent) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	for i := range events {
		_, err = tx.Exec(ctx,
			`INSERT INTO events (`+eventColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			events[i].ID,
			string(events[i].EventType),
			events[i].AssetID,
			events[i].ScanRunID,
			string(events[i].Severity),
			nullStr(events[i].Details),
			events[i].Timestamp,
		)
		if err != nil {
			return fmt.Errorf("insert event %s: %w", events[i].ID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ListEvents returns events matching the supplied filter.
func (s *PostgresStore) ListEvents(ctx context.Context, filter store.EventFilter) ([]model.AssetEvent, error) {
	var (
		clauses []string
		args    []any
		paramN  int
	)

	if filter.EventType != "" {
		paramN++
		clauses = append(clauses, fmt.Sprintf("event_type = $%d", paramN))
		args = append(args, filter.EventType)
	}
	if filter.AssetID != nil {
		paramN++
		clauses = append(clauses, fmt.Sprintf("asset_id = $%d", paramN))
		args = append(args, *filter.AssetID)
	}
	if filter.ScanRunID != nil {
		paramN++
		clauses = append(clauses, fmt.Sprintf("scan_run_id = $%d", paramN))
		args = append(args, *filter.ScanRunID)
	}

	query := `SELECT ` + eventColumns + ` FROM events`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY timestamp DESC"

	if filter.Limit > 0 {
		paramN++
		query += fmt.Sprintf(" LIMIT $%d", paramN)
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		paramN++
		query += fmt.Sprintf(" OFFSET $%d", paramN)
		args = append(args, filter.Offset)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	return scanEvents(rows)
}

// ---------------------------------------------------------------------------
// Scan runs
// ---------------------------------------------------------------------------

const scanRunColumns = `id, started_at, completed_at, status, total_assets,
	new_assets, updated_assets, stale_assets, coverage_percent,
	error_count, scope_config, discovery_sources`

// scanScanRun reads a single row into a model.ScanRun. The column order must
// match scanRunColumns exactly.
func scanScanRun(row pgx.Row) (*model.ScanRun, error) {
	var r model.ScanRun
	var (
		scopeConfig      *string
		discoverySources *string
	)
	err := row.Scan(
		&r.ID,
		&r.StartedAt,
		&r.CompletedAt,
		&r.Status,
		&r.TotalAssets,
		&r.NewAssets,
		&r.UpdatedAssets,
		&r.StaleAssets,
		&r.CoveragePercent,
		&r.ErrorCount,
		&scopeConfig,
		&discoverySources,
	)
	if err != nil {
		return nil, err
	}
	r.ScopeConfig = derefStr(scopeConfig)
	r.DiscoverySources = derefStr(discoverySources)
	return &r, nil
}

// CreateScanRun records a new scan run.
func (s *PostgresStore) CreateScanRun(ctx context.Context, run model.ScanRun) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO scan_runs (`+scanRunColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		run.ID,
		run.StartedAt,
		run.CompletedAt,
		string(run.Status),
		run.TotalAssets,
		run.NewAssets,
		run.UpdatedAssets,
		run.StaleAssets,
		run.CoveragePercent,
		run.ErrorCount,
		nullStr(run.ScopeConfig),
		nullStr(run.DiscoverySources),
	)
	if err != nil {
		return fmt.Errorf("create scan run %s: %w", run.ID, err)
	}
	return nil
}

// CompleteScanRun updates an existing scan run with the final result and marks
// it as completed.
func (s *PostgresStore) CompleteScanRun(ctx context.Context, id uuid.UUID, result model.ScanResult) error {
	now := time.Now().UTC()
	tag, err := s.pool.Exec(ctx, `
		UPDATE scan_runs SET
			completed_at     = $1,
			status           = $2,
			total_assets     = $3,
			new_assets       = $4,
			updated_assets   = $5,
			stale_assets     = $6,
			coverage_percent = $7
		WHERE id = $8`,
		now,
		string(model.ScanStatusCompleted),
		result.TotalAssets,
		result.NewAssets,
		result.UpdatedAssets,
		result.StaleAssets,
		result.CoveragePercent,
		id,
	)
	if err != nil {
		return fmt.Errorf("complete scan run %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("scan run %s not found", id)
	}
	return nil
}

// GetLatestScanRun returns the most recent scan run ordered by started_at, or
// (nil, nil) when no scan runs exist.
func (s *PostgresStore) GetLatestScanRun(ctx context.Context) (*model.ScanRun, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+scanRunColumns+` FROM scan_runs ORDER BY started_at DESC LIMIT 1`)
	r, err := scanScanRun(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get latest scan run: %w", err)
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// Installed Software
// ---------------------------------------------------------------------------

const softwareColumns = `id, asset_id, software_name, vendor, version, cpe23, package_manager`

// scanSoftware reads a single row into a model.InstalledSoftware.
func scanSoftware(row pgx.Row) (*model.InstalledSoftware, error) {
	var sw model.InstalledSoftware
	var (
		cpe23  *string
		pkgMgr *string
	)
	err := row.Scan(
		&sw.ID,
		&sw.AssetID,
		&sw.SoftwareName,
		&sw.Vendor,
		&sw.Version,
		&cpe23,
		&pkgMgr,
	)
	if err != nil {
		return nil, err
	}
	sw.CPE23 = derefStr(cpe23)
	sw.PackageManager = derefStr(pkgMgr)
	return &sw, nil
}

// UpsertSoftware replaces all installed software records for the given asset.
// It deletes existing rows and inserts the new set inside a single transaction.
func (s *PostgresStore) UpsertSoftware(ctx context.Context, assetID uuid.UUID, software []model.InstalledSoftware) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	_, err = tx.Exec(ctx,
		`DELETE FROM installed_software WHERE asset_id = $1`, assetID)
	if err != nil {
		return fmt.Errorf("delete old software for %s: %w", assetID, err)
	}

	for i := range software {
		_, err = tx.Exec(ctx,
			`INSERT INTO installed_software (`+softwareColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			software[i].ID,
			assetID,
			software[i].SoftwareName,
			software[i].Vendor,
			software[i].Version,
			nullStr(software[i].CPE23),
			nullStr(software[i].PackageManager),
		)
		if err != nil {
			return fmt.Errorf("insert software %s: %w", software[i].SoftwareName, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ListSoftware returns all installed software records for the given asset,
// ordered by software name.
func (s *PostgresStore) ListSoftware(ctx context.Context, assetID uuid.UUID) ([]model.InstalledSoftware, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+softwareColumns+` FROM installed_software WHERE asset_id = $1 ORDER BY software_name`,
		assetID,
	)
	if err != nil {
		return nil, fmt.Errorf("list software: %w", err)
	}
	defer rows.Close()

	var software []model.InstalledSoftware
	for rows.Next() {
		sw, err := scanSoftware(rows)
		if err != nil {
			return nil, fmt.Errorf("scan software row: %w", err)
		}
		software = append(software, *sw)
	}
	return software, rows.Err()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// nullStr returns a *string that is nil when s is empty, allowing PostgreSQL
// to store NULL for optional text columns.
func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// derefStr safely dereferences a *string, returning "" when the pointer is nil.
func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
