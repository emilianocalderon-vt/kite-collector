package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// SQLiteStore implements store.Store backed by a local SQLite database.
type SQLiteStore struct {
	db *sql.DB
}

// Compile-time interface check.
var _ store.Store = (*SQLiteStore)(nil)

// New opens (or creates) a SQLite database at dbPath and returns an
// initialised SQLiteStore. The connection enables WAL journal mode, a 5-second
// busy timeout, foreign key enforcement, and performance pragmas.
func New(dbPath string) (*SQLiteStore, error) {
	dsn := dbPath + "?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite open %s: %w", dbPath, err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite ping %s: %w", dbPath, err)
	}

	// Performance pragmas (session-level, not persisted in schema).
	for _, p := range []string{
		"PRAGMA synchronous = NORMAL",  // safe with WAL, ~2x faster writes
		"PRAGMA cache_size = -64000",   // 64MB page cache (default 2MB)
		"PRAGMA temp_store = MEMORY",   // temp tables in RAM
		"PRAGMA mmap_size = 268435456", // 256MB memory-mapped I/O
	} {
		if _, pErr := db.ExecContext(context.Background(), p); pErr != nil {
			_ = db.Close()
			return nil, fmt.Errorf("sqlite pragma %q: %w", p, pErr)
		}
	}

	return &SQLiteStore{db: db}, nil
}

// Close releases the underlying database connection pool.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------

const assetColumns = `id, asset_type, hostname, os_family, os_version,
	kernel_version, architecture,
	is_authorized, is_managed, environment, owner, criticality,
	discovery_source, first_seen_at, last_seen_at, tags, natural_key`

// scanAsset reads a single row from the result set into an Asset.
func scanAsset(row interface{ Scan(dest ...any) error }) (*model.Asset, error) {
	var a model.Asset
	var (
		idStr         string
		firstSeen     string
		lastSeen      string
		osFamily      sql.NullString
		osVersion     sql.NullString
		kernelVersion sql.NullString
		architecture  sql.NullString
		environment   sql.NullString
		owner         sql.NullString
		criticality   sql.NullString
		tags          sql.NullString
		naturalKey    sql.NullString
	)
	err := row.Scan(
		&idStr,
		&a.AssetType,
		&a.Hostname,
		&osFamily,
		&osVersion,
		&kernelVersion,
		&architecture,
		&a.IsAuthorized,
		&a.IsManaged,
		&environment,
		&owner,
		&criticality,
		&a.DiscoverySource,
		&firstSeen,
		&lastSeen,
		&tags,
		&naturalKey,
	)
	if err != nil {
		return nil, err
	}

	a.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("parse asset id: %w", err)
	}
	a.FirstSeenAt, err = time.Parse(time.RFC3339, firstSeen)
	if err != nil {
		return nil, fmt.Errorf("parse first_seen_at: %w", err)
	}
	a.LastSeenAt, err = time.Parse(time.RFC3339, lastSeen)
	if err != nil {
		return nil, fmt.Errorf("parse last_seen_at: %w", err)
	}
	a.OSFamily = osFamily.String
	a.OSVersion = osVersion.String
	a.KernelVersion = kernelVersion.String
	a.Architecture = architecture.String
	a.Environment = environment.String
	a.Owner = owner.String
	a.Criticality = criticality.String
	a.Tags = tags.String
	a.NaturalKey = naturalKey.String

	return &a, nil
}

// UpsertAsset inserts a new asset or replaces an existing one matched by the
// UNIQUE(hostname, asset_type) constraint. The natural key is computed before
// writing.
func (s *SQLiteStore) UpsertAsset(ctx context.Context, asset model.Asset) error {
	asset.ComputeNaturalKey()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO assets (`+assetColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(hostname, asset_type) DO UPDATE SET
			os_family        = excluded.os_family,
			os_version       = excluded.os_version,
			kernel_version   = excluded.kernel_version,
			architecture     = excluded.architecture,
			is_authorized    = excluded.is_authorized,
			is_managed       = excluded.is_managed,
			environment      = excluded.environment,
			owner            = excluded.owner,
			criticality      = excluded.criticality,
			discovery_source = excluded.discovery_source,
			last_seen_at     = excluded.last_seen_at,
			tags             = excluded.tags,
			natural_key      = excluded.natural_key
	`,
		asset.ID.String(),
		string(asset.AssetType),
		asset.Hostname,
		nullStr(asset.OSFamily),
		nullStr(asset.OSVersion),
		nullStr(asset.KernelVersion),
		nullStr(asset.Architecture),
		string(asset.IsAuthorized),
		string(asset.IsManaged),
		nullStr(asset.Environment),
		nullStr(asset.Owner),
		nullStr(asset.Criticality),
		asset.DiscoverySource,
		asset.FirstSeenAt.Format(time.RFC3339),
		asset.LastSeenAt.Format(time.RFC3339),
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
func (s *SQLiteStore) UpsertAssets(ctx context.Context, assets []model.Asset) (inserted, updated int, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Pre-compute natural keys for the whole batch.
	for i := range assets {
		assets[i].ComputeNaturalKey()
	}

	// Batch-query existing natural keys to avoid per-row SELECT COUNT(*).
	existingKeys := make(map[string]bool, len(assets))
	if len(assets) > 0 {
		placeholders := make([]string, len(assets))
		args := make([]any, len(assets))
		for i, a := range assets {
			placeholders[i] = "?"
			args[i] = a.NaturalKey
		}
		query := `SELECT natural_key FROM assets WHERE natural_key IN (` +
			strings.Join(placeholders, ",") + `)` //#nosec G202 -- placeholders are literal "?" strings, values are in args
		rows, qErr := tx.QueryContext(ctx, query, args...)
		if qErr != nil {
			return 0, 0, fmt.Errorf("batch lookup existing keys: %w", qErr)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var key string
			if scanErr := rows.Scan(&key); scanErr != nil {
				return 0, 0, fmt.Errorf("scan existing key: %w", scanErr)
			}
			existingKeys[key] = true
		}
		if rowErr := rows.Err(); rowErr != nil {
			return 0, 0, fmt.Errorf("batch lookup rows: %w", rowErr)
		}
	}

	for i := range assets {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO assets (`+assetColumns+`)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(hostname, asset_type) DO UPDATE SET
				os_family        = excluded.os_family,
				os_version       = excluded.os_version,
				kernel_version   = excluded.kernel_version,
				architecture     = excluded.architecture,
				is_authorized    = excluded.is_authorized,
				is_managed       = excluded.is_managed,
				environment      = excluded.environment,
				owner            = excluded.owner,
				criticality      = excluded.criticality,
				discovery_source = excluded.discovery_source,
				last_seen_at     = excluded.last_seen_at,
				tags             = excluded.tags,
				natural_key      = excluded.natural_key
		`,
			assets[i].ID.String(),
			string(assets[i].AssetType),
			assets[i].Hostname,
			nullStr(assets[i].OSFamily),
			nullStr(assets[i].OSVersion),
			nullStr(assets[i].KernelVersion),
			nullStr(assets[i].Architecture),
			string(assets[i].IsAuthorized),
			string(assets[i].IsManaged),
			nullStr(assets[i].Environment),
			nullStr(assets[i].Owner),
			nullStr(assets[i].Criticality),
			assets[i].DiscoverySource,
			assets[i].FirstSeenAt.Format(time.RFC3339),
			assets[i].LastSeenAt.Format(time.RFC3339),
			nullStr(assets[i].Tags),
			assets[i].NaturalKey,
		)
		if err != nil {
			return 0, 0, fmt.Errorf("upsert asset %s: %w", assets[i].ID, err)
		}

		if existingKeys[assets[i].NaturalKey] {
			updated++
		} else {
			inserted++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit tx: %w", err)
	}
	return inserted, updated, nil
}

// GetAssetByID retrieves the asset identified by id. Returns store.ErrNotFound
// when the id does not exist.
func (s *SQLiteStore) GetAssetByID(ctx context.Context, id uuid.UUID) (*model.Asset, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+assetColumns+` FROM assets WHERE id = ?`, id.String())
	a, err := scanAsset(row)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get asset by id: %w", err)
	}
	return a, nil
}

// GetAssetByNaturalKey retrieves the asset whose precomputed SHA-256 natural
// key matches key. Returns (nil, nil) when no match is found.
func (s *SQLiteStore) GetAssetByNaturalKey(ctx context.Context, key string) (*model.Asset, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+assetColumns+` FROM assets WHERE natural_key = ?`, key)
	a, err := scanAsset(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get asset by natural key: %w", err)
	}
	return a, nil
}

// ListAssets returns assets matching the supplied filter. An empty filter
// returns all assets (subject to Limit/Offset).
func (s *SQLiteStore) ListAssets(ctx context.Context, filter store.AssetFilter) ([]model.Asset, error) {
	var (
		clauses []string
		args    []any
	)

	if filter.AssetType != "" {
		clauses = append(clauses, "asset_type = ?")
		args = append(args, filter.AssetType)
	}
	if filter.IsAuthorized != "" {
		clauses = append(clauses, "is_authorized = ?")
		args = append(args, filter.IsAuthorized)
	}
	if filter.IsManaged != "" {
		clauses = append(clauses, "is_managed = ?")
		args = append(args, filter.IsManaged)
	}
	if filter.Hostname != "" {
		clauses = append(clauses, "hostname = ?")
		args = append(args, filter.Hostname)
	}

	query := `SELECT ` + assetColumns + ` FROM assets`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ") //#nosec G202 -- clauses use parameterized placeholders, values are in args
	}
	query += " ORDER BY last_seen_at DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	defer func() { _ = rows.Close() }()

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

// GetStaleAssets returns assets whose last_seen_at is older than the given
// threshold measured from the current time.
func (s *SQLiteStore) GetStaleAssets(ctx context.Context, threshold time.Duration) ([]model.Asset, error) {
	cutoff := time.Now().UTC().Add(-threshold).Format(time.RFC3339)
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+assetColumns+` FROM assets WHERE last_seen_at < ? ORDER BY last_seen_at ASC`,
		cutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("get stale assets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var assets []model.Asset
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, fmt.Errorf("scan stale asset row: %w", err)
		}
		assets = append(assets, *a)
	}
	return assets, rows.Err()
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

const eventColumns = `id, event_type, asset_id, scan_run_id, severity, details, timestamp`

// scanEvent reads a single row from the result set into an AssetEvent.
func scanEvent(row interface{ Scan(dest ...any) error }) (*model.AssetEvent, error) {
	var e model.AssetEvent
	var (
		idStr      string
		assetIDStr string
		scanIDStr  string
		details    sql.NullString
		ts         string
	)
	err := row.Scan(
		&idStr,
		&e.EventType,
		&assetIDStr,
		&scanIDStr,
		&e.Severity,
		&details,
		&ts,
	)
	if err != nil {
		return nil, err
	}

	e.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("parse event id: %w", err)
	}
	e.AssetID, err = uuid.Parse(assetIDStr)
	if err != nil {
		return nil, fmt.Errorf("parse event asset_id: %w", err)
	}
	e.ScanRunID, err = uuid.Parse(scanIDStr)
	if err != nil {
		return nil, fmt.Errorf("parse event scan_run_id: %w", err)
	}
	e.Timestamp, err = time.Parse(time.RFC3339, ts)
	if err != nil {
		return nil, fmt.Errorf("parse event timestamp: %w", err)
	}
	e.Details = details.String

	return &e, nil
}

// InsertEvent persists a single asset lifecycle event.
func (s *SQLiteStore) InsertEvent(ctx context.Context, event model.AssetEvent) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO events (`+eventColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		event.ID.String(),
		string(event.EventType),
		event.AssetID.String(),
		event.ScanRunID.String(),
		string(event.Severity),
		nullStr(event.Details),
		event.Timestamp.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert event %s: %w", event.ID, err)
	}
	return nil
}

// InsertEvents persists a batch of events inside a single transaction.
func (s *SQLiteStore) InsertEvents(ctx context.Context, events []model.AssetEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO events (`+eventColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare insert event: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for i := range events {
		_, err := stmt.ExecContext(ctx,
			events[i].ID.String(),
			string(events[i].EventType),
			events[i].AssetID.String(),
			events[i].ScanRunID.String(),
			string(events[i].Severity),
			nullStr(events[i].Details),
			events[i].Timestamp.Format(time.RFC3339),
		)
		if err != nil {
			return fmt.Errorf("insert event %s: %w", events[i].ID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ListEvents returns events matching the supplied filter.
func (s *SQLiteStore) ListEvents(ctx context.Context, filter store.EventFilter) ([]model.AssetEvent, error) {
	var (
		clauses []string
		args    []any
	)

	if filter.EventType != "" {
		clauses = append(clauses, "event_type = ?")
		args = append(args, filter.EventType)
	}
	if filter.AssetID != nil {
		clauses = append(clauses, "asset_id = ?")
		args = append(args, filter.AssetID.String())
	}
	if filter.ScanRunID != nil {
		clauses = append(clauses, "scan_run_id = ?")
		args = append(args, filter.ScanRunID.String())
	}

	query := `SELECT ` + eventColumns + ` FROM events`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ") //#nosec G202 -- clauses use parameterized placeholders, values are in args
	}
	query += " ORDER BY timestamp DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	defer func() { _ = rows.Close() }()

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

// ---------------------------------------------------------------------------
// Scan runs
// ---------------------------------------------------------------------------

const scanRunColumns = `id, started_at, completed_at, status, total_assets,
	new_assets, updated_assets, stale_assets, coverage_percent,
	error_count, scope_config, discovery_sources`

// scanScanRun reads a single row from the result set into a ScanRun.
func scanScanRun(row interface{ Scan(dest ...any) error }) (*model.ScanRun, error) {
	var r model.ScanRun
	var (
		idStr            string
		startedAt        string
		completedAt      sql.NullString
		scopeConfig      sql.NullString
		discoverySources sql.NullString
	)
	err := row.Scan(
		&idStr,
		&startedAt,
		&completedAt,
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

	r.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("parse scan run id: %w", err)
	}
	r.StartedAt, err = time.Parse(time.RFC3339, startedAt)
	if err != nil {
		return nil, fmt.Errorf("parse started_at: %w", err)
	}
	if completedAt.Valid {
		t, err := time.Parse(time.RFC3339, completedAt.String)
		if err != nil {
			return nil, fmt.Errorf("parse completed_at: %w", err)
		}
		r.CompletedAt = &t
	}
	r.ScopeConfig = scopeConfig.String
	r.DiscoverySources = discoverySources.String

	return &r, nil
}

// CreateScanRun records a new scan run.
func (s *SQLiteStore) CreateScanRun(ctx context.Context, run model.ScanRun) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scan_runs (`+scanRunColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.ID.String(),
		run.StartedAt.Format(time.RFC3339),
		nullTimePtr(run.CompletedAt),
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
// it as completed (or failed when the result carries a non-completed status).
func (s *SQLiteStore) CompleteScanRun(ctx context.Context, id uuid.UUID, result model.ScanResult) error {
	now := time.Now().UTC().Format(time.RFC3339)
	status := string(model.ScanStatusCompleted)
	if result.Status != "" {
		status = result.Status
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE scan_runs SET
			completed_at     = ?,
			status           = ?,
			total_assets     = ?,
			new_assets       = ?,
			updated_assets   = ?,
			stale_assets     = ?,
			coverage_percent = ?,
			error_count      = ?
		WHERE id = ?`,
		now,
		status,
		result.TotalAssets,
		result.NewAssets,
		result.UpdatedAssets,
		result.StaleAssets,
		result.CoveragePercent,
		result.ErrorCount,
		id.String(),
	)
	if err != nil {
		return fmt.Errorf("complete scan run %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("scan run %s not found", id)
	}
	return nil
}

// GetLatestScanRun returns the most recent scan run ordered by started_at, or
// (nil, nil) when no scan runs exist.
func (s *SQLiteStore) GetLatestScanRun(ctx context.Context) (*model.ScanRun, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+scanRunColumns+` FROM scan_runs ORDER BY started_at DESC LIMIT 1`)
	r, err := scanScanRun(row)
	if err == sql.ErrNoRows {
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

const softwareColumns = `id, asset_id, software_name, vendor, version, cpe23, package_manager, architecture`

// scanSoftware reads a single row from the result set into an InstalledSoftware.
func scanSoftware(row interface{ Scan(dest ...any) error }) (*model.InstalledSoftware, error) {
	var s model.InstalledSoftware
	var (
		idStr      string
		assetIDStr string
		vendor     sql.NullString
		cpe23      sql.NullString
		pkgMgr     sql.NullString
		arch       sql.NullString
	)
	err := row.Scan(
		&idStr,
		&assetIDStr,
		&s.SoftwareName,
		&vendor,
		&s.Version,
		&cpe23,
		&pkgMgr,
		&arch,
	)
	if err != nil {
		return nil, err
	}

	s.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("parse software id: %w", err)
	}
	s.AssetID, err = uuid.Parse(assetIDStr)
	if err != nil {
		return nil, fmt.Errorf("parse software asset_id: %w", err)
	}
	s.Vendor = vendor.String
	s.CPE23 = cpe23.String
	s.PackageManager = pkgMgr.String
	s.Architecture = arch.String

	return &s, nil
}

// UpsertSoftware replaces all installed software records for the given asset.
// It deletes existing rows and inserts the new set inside a single transaction.
func (s *SQLiteStore) UpsertSoftware(ctx context.Context, assetID uuid.UUID, software []model.InstalledSoftware) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	_, err = tx.ExecContext(ctx,
		`DELETE FROM installed_software WHERE asset_id = ?`, assetID.String())
	if err != nil {
		return fmt.Errorf("delete old software for %s: %w", assetID, err)
	}

	if len(software) == 0 {
		return tx.Commit()
	}

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO installed_software (`+softwareColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare insert software: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for i := range software {
		_, err = stmt.ExecContext(ctx,
			software[i].ID.String(),
			assetID.String(),
			software[i].SoftwareName,
			software[i].Vendor, // NOT NULL DEFAULT '' in schema
			software[i].Version,
			nullStr(software[i].CPE23),
			nullStr(software[i].PackageManager),
			nullStr(software[i].Architecture),
		)
		if err != nil {
			return fmt.Errorf("insert software %s: %w", software[i].SoftwareName, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ListSoftware returns all installed software records for the given asset,
// ordered by software name.
func (s *SQLiteStore) ListSoftware(ctx context.Context, assetID uuid.UUID) ([]model.InstalledSoftware, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+softwareColumns+` FROM installed_software WHERE asset_id = ? ORDER BY software_name`,
		assetID.String(),
	)
	if err != nil {
		return nil, fmt.Errorf("list software: %w", err)
	}
	defer func() { _ = rows.Close() }()

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
// Config Findings
// ---------------------------------------------------------------------------

const findingColumns = `id, asset_id, scan_run_id, auditor, check_id, title,
	severity, cwe_id, cwe_name, evidence, expected, remediation,
	cis_control, timestamp`

// scanFinding reads a single row into a ConfigFinding.
func scanFinding(row interface{ Scan(dest ...any) error }) (*model.ConfigFinding, error) {
	var f model.ConfigFinding
	var (
		idStr      string
		assetIDStr string
		scanIDStr  string
		expected   sql.NullString
		remediation sql.NullString
		cisControl sql.NullString
		ts         string
	)
	err := row.Scan(
		&idStr,
		&assetIDStr,
		&scanIDStr,
		&f.Auditor,
		&f.CheckID,
		&f.Title,
		&f.Severity,
		&f.CWEID,
		&f.CWEName,
		&f.Evidence,
		&expected,
		&remediation,
		&cisControl,
		&ts,
	)
	if err != nil {
		return nil, err
	}

	f.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("parse finding id: %w", err)
	}
	f.AssetID, err = uuid.Parse(assetIDStr)
	if err != nil {
		return nil, fmt.Errorf("parse finding asset_id: %w", err)
	}
	f.ScanRunID, err = uuid.Parse(scanIDStr)
	if err != nil {
		return nil, fmt.Errorf("parse finding scan_run_id: %w", err)
	}
	f.Timestamp, err = time.Parse(time.RFC3339, ts)
	if err != nil {
		return nil, fmt.Errorf("parse finding timestamp: %w", err)
	}
	f.Expected = expected.String
	f.Remediation = remediation.String
	f.CISControl = cisControl.String

	return &f, nil
}

// InsertFindings persists a batch of config findings inside a single transaction.
func (s *SQLiteStore) InsertFindings(ctx context.Context, findings []model.ConfigFinding) error {
	if len(findings) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO config_findings (`+findingColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare insert finding: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for i := range findings {
		_, err := stmt.ExecContext(ctx,
			findings[i].ID.String(),
			findings[i].AssetID.String(),
			findings[i].ScanRunID.String(),
			findings[i].Auditor,
			findings[i].CheckID,
			findings[i].Title,
			string(findings[i].Severity),
			findings[i].CWEID,
			findings[i].CWEName,
			findings[i].Evidence,
			findings[i].Expected,
			findings[i].Remediation,
			findings[i].CISControl,
			findings[i].Timestamp.Format(time.RFC3339),
		)
		if err != nil {
			return fmt.Errorf("insert finding %s: %w", findings[i].ID, err)
		}
	}

	return tx.Commit()
}

// ListFindings returns config findings matching the supplied filter.
func (s *SQLiteStore) ListFindings(ctx context.Context, filter store.FindingFilter) ([]model.ConfigFinding, error) {
	var (
		clauses []string
		args    []any
	)

	if filter.AssetID != nil {
		clauses = append(clauses, "asset_id = ?")
		args = append(args, filter.AssetID.String())
	}
	if filter.ScanRunID != nil {
		clauses = append(clauses, "scan_run_id = ?")
		args = append(args, filter.ScanRunID.String())
	}
	if filter.Auditor != "" {
		clauses = append(clauses, "auditor = ?")
		args = append(args, filter.Auditor)
	}
	if filter.Severity != "" {
		clauses = append(clauses, "severity = ?")
		args = append(args, filter.Severity)
	}
	if filter.CWEID != "" {
		clauses = append(clauses, "cwe_id = ?")
		args = append(args, filter.CWEID)
	}

	query := `SELECT ` + findingColumns + ` FROM config_findings`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ") //#nosec G202 -- clauses use parameterized placeholders
	}
	query += " ORDER BY timestamp DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var findings []model.ConfigFinding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("scan finding row: %w", err)
		}
		findings = append(findings, *f)
	}
	return findings, rows.Err()
}

// ---------------------------------------------------------------------------
// Posture Assessments
// ---------------------------------------------------------------------------

const postureColumns = `id, asset_id, scan_run_id, capec_id, capec_name,
	finding_ids, likelihood, mitigation, timestamp`

// scanPosture reads a single row into a PostureAssessment.
func scanPosture(row interface{ Scan(dest ...any) error }) (*model.PostureAssessment, error) {
	var p model.PostureAssessment
	var (
		idStr      string
		assetIDStr string
		scanIDStr  string
		findingIDs string
		mitigation sql.NullString
		ts         string
	)
	err := row.Scan(
		&idStr,
		&assetIDStr,
		&scanIDStr,
		&p.CAPECID,
		&p.CAPECName,
		&findingIDs,
		&p.Likelihood,
		&mitigation,
		&ts,
	)
	if err != nil {
		return nil, err
	}

	p.ID, err = uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("parse posture id: %w", err)
	}
	p.AssetID, err = uuid.Parse(assetIDStr)
	if err != nil {
		return nil, fmt.Errorf("parse posture asset_id: %w", err)
	}
	p.ScanRunID, err = uuid.Parse(scanIDStr)
	if err != nil {
		return nil, fmt.Errorf("parse posture scan_run_id: %w", err)
	}
	p.Timestamp, err = time.Parse(time.RFC3339, ts)
	if err != nil {
		return nil, fmt.Errorf("parse posture timestamp: %w", err)
	}
	p.Mitigation = mitigation.String

	// Parse JSON array of finding UUIDs.
	if findingIDs != "" && findingIDs != "[]" {
		var ids []string
		if jsonErr := json.Unmarshal([]byte(findingIDs), &ids); jsonErr == nil {
			for _, idS := range ids {
				if fid, parseErr := uuid.Parse(idS); parseErr == nil {
					p.FindingIDs = append(p.FindingIDs, fid)
				}
			}
		}
	}

	return &p, nil
}

// InsertPostureAssessments persists a batch of posture assessments.
func (s *SQLiteStore) InsertPostureAssessments(ctx context.Context, assessments []model.PostureAssessment) error {
	if len(assessments) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO posture_assessments (`+postureColumns+`)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare insert posture: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for i := range assessments {
		ids := make([]string, len(assessments[i].FindingIDs))
		for j, fid := range assessments[i].FindingIDs {
			ids[j] = fid.String()
		}
		idsJSON, _ := json.Marshal(ids)

		_, err := stmt.ExecContext(ctx,
			assessments[i].ID.String(),
			assessments[i].AssetID.String(),
			assessments[i].ScanRunID.String(),
			assessments[i].CAPECID,
			assessments[i].CAPECName,
			string(idsJSON),
			string(assessments[i].Likelihood),
			assessments[i].Mitigation,
			assessments[i].Timestamp.Format(time.RFC3339),
		)
		if err != nil {
			return fmt.Errorf("insert posture %s: %w", assessments[i].ID, err)
		}
	}

	return tx.Commit()
}

// ListPostureAssessments returns posture assessments matching the filter.
func (s *SQLiteStore) ListPostureAssessments(ctx context.Context, filter store.PostureFilter) ([]model.PostureAssessment, error) {
	var (
		clauses []string
		args    []any
	)

	if filter.AssetID != nil {
		clauses = append(clauses, "asset_id = ?")
		args = append(args, filter.AssetID.String())
	}
	if filter.ScanRunID != nil {
		clauses = append(clauses, "scan_run_id = ?")
		args = append(args, filter.ScanRunID.String())
	}
	if filter.CAPECID != "" {
		clauses = append(clauses, "capec_id = ?")
		args = append(args, filter.CAPECID)
	}

	query := `SELECT ` + postureColumns + ` FROM posture_assessments`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ") //#nosec G202 -- clauses use parameterized placeholders
	}
	query += " ORDER BY timestamp DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list posture assessments: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var assessments []model.PostureAssessment
	for rows.Next() {
		p, err := scanPosture(rows)
		if err != nil {
			return nil, fmt.Errorf("scan posture row: %w", err)
		}
		assessments = append(assessments, *p)
	}
	return assessments, rows.Err()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// nullStr returns a sql.NullString that is NULL when s is empty.
func nullStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// nullTimePtr formats a *time.Time as an RFC3339 sql.NullString, NULL when nil.
func nullTimePtr(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: t.Format(time.RFC3339), Valid: true}
}
