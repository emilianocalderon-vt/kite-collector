// Package postgres provides a PostgreSQL-backed implementation of store.Store
// using pgx/v5 with connection pooling. It is safe for concurrent use and works
// with CGO_ENABLED=0 (pgx is pure Go).
package postgres

import (
	"context"
	"encoding/json"
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
// pool with bounded resource limits. The pool verifies connectivity lazily on
// first use.
func New(dsn string) (*PostgresStore, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres parse config: %w", err)
	}

	config.MaxConns = 25
	config.MinConns = 2
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute
	config.ConnConfig.ConnectTimeout = 10 * time.Second

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
	kernel_version, architecture, is_authorized, is_managed, environment, owner, criticality,
	discovery_source, first_seen_at, last_seen_at, tags, natural_key`

// scanAsset reads a single row into a model.Asset. The column order must match
// assetColumns exactly.
func scanAsset(row pgx.Row) (*model.Asset, error) {
	var a model.Asset
	var (
		osFamily      *string
		osVersion     *string
		kernelVersion *string
		architecture  *string
		environment   *string
		owner         *string
		criticality   *string
		tags          *string
		naturalKey    *string
	)
	err := row.Scan(
		&a.ID,
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
	a.KernelVersion = derefStr(kernelVersion)
	a.Architecture = derefStr(architecture)
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
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		ON CONFLICT(hostname, asset_type) DO UPDATE SET
			os_family        = EXCLUDED.os_family,
			os_version       = EXCLUDED.os_version,
			kernel_version   = EXCLUDED.kernel_version,
			architecture     = EXCLUDED.architecture,
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
		nullStr(asset.KernelVersion),
		nullStr(asset.Architecture),
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
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
			ON CONFLICT(hostname, asset_type) DO UPDATE SET
				os_family        = EXCLUDED.os_family,
				os_version       = EXCLUDED.os_version,
				kernel_version   = EXCLUDED.kernel_version,
				architecture     = EXCLUDED.architecture,
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
			nullStr(assets[i].KernelVersion),
			nullStr(assets[i].Architecture),
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

// GetAssetByID retrieves the asset identified by id. Returns store.ErrNotFound
// when the id does not exist.
func (s *PostgresStore) GetAssetByID(ctx context.Context, id uuid.UUID) (*model.Asset, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+assetColumns+` FROM assets WHERE id = $1`, id)
	a, err := scanAsset(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get asset by id: %w", err)
	}
	return a, nil
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
// it as completed (or failed when the result carries a non-completed status).
func (s *PostgresStore) CompleteScanRun(ctx context.Context, id uuid.UUID, result model.ScanResult) error {
	now := time.Now().UTC()
	status := string(model.ScanStatusCompleted)
	if result.Status != "" {
		status = result.Status
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE scan_runs SET
			completed_at     = $1,
			status           = $2,
			total_assets     = $3,
			new_assets       = $4,
			updated_assets   = $5,
			stale_assets     = $6,
			coverage_percent = $7,
			error_count      = $8
		WHERE id = $9`,
		now,
		status,
		result.TotalAssets,
		result.NewAssets,
		result.UpdatedAssets,
		result.StaleAssets,
		result.CoveragePercent,
		result.ErrorCount,
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

const softwareColumns = `id, asset_id, software_name, vendor, version, cpe23, package_manager, architecture`

// scanSoftware reads a single row into a model.InstalledSoftware.
func scanSoftware(row pgx.Row) (*model.InstalledSoftware, error) {
	var sw model.InstalledSoftware
	var (
		cpe23  *string
		pkgMgr *string
		arch   *string
	)
	err := row.Scan(
		&sw.ID,
		&sw.AssetID,
		&sw.SoftwareName,
		&sw.Vendor,
		&sw.Version,
		&cpe23,
		&pkgMgr,
		&arch,
	)
	if err != nil {
		return nil, err
	}
	sw.CPE23 = derefStr(cpe23)
	sw.PackageManager = derefStr(pkgMgr)
	sw.Architecture = derefStr(arch)
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
			`INSERT INTO installed_software (`+softwareColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			software[i].ID,
			assetID,
			software[i].SoftwareName,
			software[i].Vendor,
			software[i].Version,
			nullStr(software[i].CPE23),
			nullStr(software[i].PackageManager),
			nullStr(software[i].Architecture),
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
// Config Findings
// ---------------------------------------------------------------------------

const findingColumns = `id, asset_id, scan_run_id, auditor, check_id, title,
	severity, cwe_id, cwe_name, evidence, expected, remediation, cis_control, timestamp`

// scanFinding reads a single row into a model.ConfigFinding. The column order
// must match findingColumns exactly.
func scanFinding(row pgx.Row) (*model.ConfigFinding, error) {
	var f model.ConfigFinding
	var (
		cweName     *string
		evidence    *string
		expected    *string
		remediation *string
		cisControl  *string
	)
	err := row.Scan(
		&f.ID,
		&f.AssetID,
		&f.ScanRunID,
		&f.Auditor,
		&f.CheckID,
		&f.Title,
		&f.Severity,
		&f.CWEID,
		&cweName,
		&evidence,
		&expected,
		&remediation,
		&cisControl,
		&f.Timestamp,
	)
	if err != nil {
		return nil, err
	}
	f.CWEName = derefStr(cweName)
	f.Evidence = derefStr(evidence)
	f.Expected = derefStr(expected)
	f.Remediation = derefStr(remediation)
	f.CISControl = derefStr(cisControl)
	return &f, nil
}

// scanFindings collects all rows from a pgx.Rows result set into a slice.
func scanFindings(rows pgx.Rows) ([]model.ConfigFinding, error) {
	defer rows.Close()
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

// InsertFindings persists a batch of config findings inside a single transaction.
func (s *PostgresStore) InsertFindings(ctx context.Context, findings []model.ConfigFinding) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	for i := range findings {
		_, err = tx.Exec(ctx,
			`INSERT INTO config_findings (`+findingColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
			findings[i].ID,
			findings[i].AssetID,
			findings[i].ScanRunID,
			findings[i].Auditor,
			findings[i].CheckID,
			findings[i].Title,
			string(findings[i].Severity),
			findings[i].CWEID,
			nullStr(findings[i].CWEName),
			nullStr(findings[i].Evidence),
			nullStr(findings[i].Expected),
			nullStr(findings[i].Remediation),
			nullStr(findings[i].CISControl),
			findings[i].Timestamp,
		)
		if err != nil {
			return fmt.Errorf("insert finding %s: %w", findings[i].ID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ListFindings returns config findings matching the supplied filter.
func (s *PostgresStore) ListFindings(ctx context.Context, filter store.FindingFilter) ([]model.ConfigFinding, error) {
	var (
		clauses []string
		args    []any
		paramN  int
	)

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
	if filter.Auditor != "" {
		paramN++
		clauses = append(clauses, fmt.Sprintf("auditor = $%d", paramN))
		args = append(args, filter.Auditor)
	}
	if filter.Severity != "" {
		paramN++
		clauses = append(clauses, fmt.Sprintf("severity = $%d", paramN))
		args = append(args, filter.Severity)
	}
	if filter.CWEID != "" {
		paramN++
		clauses = append(clauses, fmt.Sprintf("cwe_id = $%d", paramN))
		args = append(args, filter.CWEID)
	}

	query := `SELECT ` + findingColumns + ` FROM config_findings`
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
		return nil, fmt.Errorf("list findings: %w", err)
	}
	return scanFindings(rows)
}

// ---------------------------------------------------------------------------
// Posture Assessments
// ---------------------------------------------------------------------------

const postureColumns = `id, asset_id, scan_run_id, capec_id, capec_name,
	finding_ids, likelihood, mitigation, timestamp`

// scanPosture reads a single row into a model.PostureAssessment. The column
// order must match postureColumns exactly. finding_ids is stored as JSONB.
func scanPosture(row pgx.Row) (*model.PostureAssessment, error) {
	var p model.PostureAssessment
	var (
		capecName  *string
		findingIDs []byte
		mitigation *string
	)
	err := row.Scan(
		&p.ID,
		&p.AssetID,
		&p.ScanRunID,
		&p.CAPECID,
		&capecName,
		&findingIDs,
		&p.Likelihood,
		&mitigation,
		&p.Timestamp,
	)
	if err != nil {
		return nil, err
	}
	p.CAPECName = derefStr(capecName)
	p.Mitigation = derefStr(mitigation)
	if findingIDs != nil {
		if err := json.Unmarshal(findingIDs, &p.FindingIDs); err != nil {
			return nil, fmt.Errorf("unmarshal finding_ids: %w", err)
		}
	}
	return &p, nil
}

// scanPostures collects all rows from a pgx.Rows result set into a slice.
func scanPostures(rows pgx.Rows) ([]model.PostureAssessment, error) {
	defer rows.Close()
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

// InsertPostureAssessments persists a batch of posture assessments inside a
// single transaction. FindingIDs are stored as JSONB.
func (s *PostgresStore) InsertPostureAssessments(ctx context.Context, assessments []model.PostureAssessment) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	for i := range assessments {
		findingIDs, err := json.Marshal(assessments[i].FindingIDs)
		if err != nil {
			return fmt.Errorf("marshal finding_ids for %s: %w", assessments[i].ID, err)
		}

		_, err = tx.Exec(ctx,
			`INSERT INTO posture_assessments (`+postureColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			assessments[i].ID,
			assessments[i].AssetID,
			assessments[i].ScanRunID,
			assessments[i].CAPECID,
			nullStr(assessments[i].CAPECName),
			findingIDs,
			string(assessments[i].Likelihood),
			nullStr(assessments[i].Mitigation),
			assessments[i].Timestamp,
		)
		if err != nil {
			return fmt.Errorf("insert posture assessment %s: %w", assessments[i].ID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// ListPostureAssessments returns posture assessments matching the supplied filter.
func (s *PostgresStore) ListPostureAssessments(ctx context.Context, filter store.PostureFilter) ([]model.PostureAssessment, error) {
	var (
		clauses []string
		args    []any
		paramN  int
	)

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
	if filter.CAPECID != "" {
		paramN++
		clauses = append(clauses, fmt.Sprintf("capec_id = $%d", paramN))
		args = append(args, filter.CAPECID)
	}

	query := `SELECT ` + postureColumns + ` FROM posture_assessments`
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
		return nil, fmt.Errorf("list posture assessments: %w", err)
	}
	return scanPostures(rows)
}

// ---------------------------------------------------------------------------
// Runtime Incidents
// ---------------------------------------------------------------------------

func (s *PostgresStore) InsertRuntimeIncident(ctx context.Context, incident model.RuntimeIncident) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO runtime_incidents
		(id, incident_type, component, error_message, stack_trace, scan_run_id,
		 severity, recovered, error_code, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		incident.ID,
		string(incident.IncidentType),
		incident.Component,
		incident.ErrorMessage,
		nullStr(incident.StackTrace),
		incident.ScanRunID,
		incident.Severity,
		incident.Recovered,
		nullStr(incident.ErrorCode),
		incident.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert runtime incident %s: %w", incident.ID, err)
	}
	return nil
}

func (s *PostgresStore) ListRuntimeIncidents(ctx context.Context, filter store.IncidentFilter) ([]model.RuntimeIncident, error) {
	var (
		clauses []string
		args    []any
		paramN  int
	)

	if filter.ScanRunID != nil {
		paramN++
		clauses = append(clauses, fmt.Sprintf("scan_run_id = $%d", paramN))
		args = append(args, *filter.ScanRunID)
	}
	if filter.IncidentType != "" {
		paramN++
		clauses = append(clauses, fmt.Sprintf("incident_type = $%d", paramN))
		args = append(args, filter.IncidentType)
	}
	if filter.Since != nil {
		paramN++
		clauses = append(clauses, fmt.Sprintf("created_at >= $%d", paramN))
		args = append(args, *filter.Since)
	}

	query := `SELECT id, incident_type, component, error_message, stack_trace,
		scan_run_id, severity, recovered, error_code, created_at
		FROM runtime_incidents`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY created_at DESC"

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
		return nil, fmt.Errorf("list runtime incidents: %w", err)
	}
	defer rows.Close()

	var incidents []model.RuntimeIncident
	for rows.Next() {
		var inc model.RuntimeIncident
		var stackTrace, errorCode *string
		err := rows.Scan(
			&inc.ID,
			&inc.IncidentType,
			&inc.Component,
			&inc.ErrorMessage,
			&stackTrace,
			&inc.ScanRunID,
			&inc.Severity,
			&inc.Recovered,
			&errorCode,
			&inc.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan incident row: %w", err)
		}
		inc.StackTrace = derefStr(stackTrace)
		inc.ErrorCode = derefStr(errorCode)
		incidents = append(incidents, inc)
	}
	return incidents, rows.Err()
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
