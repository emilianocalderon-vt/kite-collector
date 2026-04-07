package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnertrack/kite-collector/api/rest"
	"github.com/vulnertrack/kite-collector/internal/autodiscovery"
	"github.com/vulnertrack/kite-collector/internal/dashboard"
	kiteerrors "github.com/vulnertrack/kite-collector/internal/errors"
	"github.com/vulnertrack/kite-collector/internal/osutil"
	"github.com/vulnertrack/kite-collector/internal/classifier"
	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/dedup"
	"github.com/vulnertrack/kite-collector/internal/discovery"
	"github.com/vulnertrack/kite-collector/internal/discovery/agent"
	"github.com/vulnertrack/kite-collector/internal/discovery/cloud"
	"github.com/vulnertrack/kite-collector/internal/discovery/cmdb"
	dockerdisc "github.com/vulnertrack/kite-collector/internal/discovery/docker"
	"github.com/vulnertrack/kite-collector/internal/discovery/mdm"
	"github.com/vulnertrack/kite-collector/internal/discovery/network"
	"github.com/vulnertrack/kite-collector/internal/discovery/paas"
	"github.com/vulnertrack/kite-collector/internal/discovery/proxmox"
	"github.com/vulnertrack/kite-collector/internal/discovery/snmp"
	"github.com/vulnertrack/kite-collector/internal/discovery/unifi"
	"github.com/vulnertrack/kite-collector/internal/discovery/vps"
	wazuhdisc "github.com/vulnertrack/kite-collector/internal/discovery/wazuh"
	"github.com/vulnertrack/kite-collector/internal/emitter"
	"github.com/vulnertrack/kite-collector/internal/engine"
	"github.com/vulnertrack/kite-collector/internal/metrics"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/policy"
	"github.com/vulnertrack/kite-collector/internal/store"
	"github.com/vulnertrack/kite-collector/internal/store/postgres"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

// Build-time variables set via ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// ---------------------------------------------------------------------------
// Diff types
// ---------------------------------------------------------------------------

// DiffResult holds the outcome of comparing two asset databases.
type DiffResult struct {
	New       []model.Asset
	Removed   []model.Asset
	Changed   []ChangedAsset
	Unchanged []model.Asset
}

// ChangedAsset pairs the before and after state of a modified asset along
// with a list of field names that differ.
type ChangedAsset struct {
	Fields []string // changed field names
	Before model.Asset
	After  model.Asset
}

// ---------------------------------------------------------------------------
// Root command
// ---------------------------------------------------------------------------

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "kite-collector",
		Short: "Cybersecurity asset discovery and classification agent",
		Long: `kite-collector discovers, deduplicates, classifies, and tracks IT assets
on your network. It stores results in a local SQLite database and can emit
lifecycle events for downstream consumption.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(
		newScanCmd(),
		newAgentCmd(),
		newDiffCmd(),
		newReportCmd(),
		newDiscoverServicesCmd(),
		newInitCmd(),
		newQueryCmd(),
		newDBCmd(),
		newMigrateCmd(),
		newDashboardCmd(),
		newVersionCmd(),
		newErrorCmd(),
	)

	return root
}

// ---------------------------------------------------------------------------
// scan command
// ---------------------------------------------------------------------------

func newScanCmd() *cobra.Command {
	var (
		cfgFile       string
		scope         []string
		output        string
		dbPath        string
		sources       []string
		verbose       bool
		autoDiscovery bool
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run an asset discovery scan",
		Long: `Execute a full scan cycle: discover assets from enabled sources, deduplicate
against the local database, classify authorization and managed state, evaluate
policy rules, persist results, and emit lifecycle events.

Use --auto to run infrastructure auto-discovery first and enable all ready
sources automatically.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cfgFile, scope, output, dbPath, sources, verbose, autoDiscovery)
		},
	}

	cmd.Flags().StringVar(&cfgFile, "config", "kite-collector.yaml", "path to configuration file")
	cmd.Flags().StringSliceVar(&scope, "scope", nil, "CIDR scopes (overrides config)")
	cmd.Flags().StringVar(&output, "output", "table", "output format: json, csv, table")
	cmd.Flags().StringVar(&dbPath, "db", "./kite.db", "path to SQLite database")
	cmd.Flags().StringSliceVar(&sources, "source", nil, "discovery sources to enable")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable debug logging")
	cmd.Flags().BoolVar(&autoDiscovery, "auto", false, "auto-discover infrastructure services and enable ready sources")

	return cmd
}

func runScan(cfgFile string, scope []string, output, dbPath string, sources []string, verbose, autoDiscover bool) error {
	// Set up context with signal handling.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Load configuration. Use defaults when the config file is absent.
	var cfg *config.Config
	if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
		c, loadErr := config.Load("")
		if loadErr != nil {
			return fmt.Errorf("load default config: %w", loadErr)
		}
		cfg = c
	} else {
		c, loadErr := config.Load(cfgFile)
		if loadErr != nil {
			return fmt.Errorf("load config %s: %w", cfgFile, loadErr)
		}
		cfg = c
	}

	// Auto-discovery: detect available infrastructure services and enable
	// all ready sources in the config before scanning.
	if autoDiscover {
		discovered := autodiscovery.Run(ctx, autodiscovery.Options{})
		if cfg.Discovery.Sources == nil {
			cfg.Discovery.Sources = make(map[string]config.SourceConfig)
		}
		readyCount := 0
		for _, svc := range discovered {
			if svc.Status != "ready" {
				continue
			}
			src := cfg.Discovery.Sources[svc.Name]
			src.Enabled = true
			if svc.Endpoint != "" {
				src.Endpoint = svc.Endpoint
			}
			cfg.Discovery.Sources[svc.Name] = src
			readyCount++
		}
		_, _ = fmt.Fprintf(os.Stderr, "Auto-discovery: %d services found, %d ready and enabled\n",
			len(discovered), readyCount)
	}

	// Override scope from flag if provided.
	if len(scope) > 0 {
		if cfg.Discovery.Sources == nil {
			cfg.Discovery.Sources = make(map[string]config.SourceConfig)
		}
		netCfg := cfg.Discovery.Sources["network"]
		netCfg.Enabled = true
		netCfg.Scope = scope
		cfg.Discovery.Sources["network"] = netCfg
	}

	// Validate configuration early.
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config validation: %w", err)
	}

	// Configure structured logger.
	logLevel := slog.LevelInfo
	if verbose || strings.EqualFold(cfg.LogLevel, "debug") {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	// Ensure data directory exists.
	dataDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir %s: %w", dataDir, err)
	}

	// Open SQLite store and run migrations.
	st, err := sqlite.New(dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = st.Close() }()

	if err = st.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate store: %w", err)
	}

	// Set up discovery registry.
	registry := discovery.NewRegistry()
	registry.Register(network.New())
	registry.Register(agent.New())
	registry.Register(cloud.NewAWS())
	registry.Register(cloud.NewGCP())
	registry.Register(cloud.NewAzure())
	registry.Register(mdm.NewJamf())
	registry.Register(mdm.NewIntune())
	registry.Register(mdm.NewSCCM())
	registry.Register(cmdb.NewServiceNow())
	registry.Register(cmdb.NewNetBox())
	registry.Register(dockerdisc.New())
	registry.Register(unifi.New())
	registry.Register(proxmox.New())
	registry.Register(snmp.New())
	registry.Register(vps.NewHetzner())
	registry.Register(vps.NewDigitalOcean())
	registry.Register(vps.NewVultr())
	registry.Register(vps.NewHostinger())
	registry.Register(vps.NewLinode())
	registry.Register(vps.NewScaleway())
	registry.Register(vps.NewOVHcloud())
	registry.Register(vps.NewUpCloud())
	registry.Register(vps.NewKamatera())
	registry.Register(wazuhdisc.New())
	registry.Register(paas.NewHeroku())
	registry.Register(paas.NewRender())
	registry.Register(paas.NewFlyIO())
	registry.Register(paas.NewRailway())
	registry.Register(paas.NewVercel())
	registry.Register(paas.NewCoolify())
	registry.Register(paas.NewCapRover())

	// Set up metrics.
	met := metrics.New()
	var metricsSrv *http.Server
	if cfg.Metrics.Enabled {
		listen := cfg.Metrics.Listen
		if listen == "" {
			listen = ":9090"
		}
		metricsSrv = met.Serve(listen)
	}

	// Set up deduplicator.
	dd := dedup.New(st, met)

	// Set up classifier.
	authorizer, err := classifier.NewAuthorizer(
		cfg.Classification.Authorization.AllowlistFile,
		cfg.Classification.Authorization.MatchFields,
	)
	if err != nil {
		return fmt.Errorf("create authorizer: %w", err)
	}
	manager := classifier.NewManager(cfg.Classification.Managed.RequiredControls)
	cls := classifier.New(authorizer, manager)

	// Set up noop emitter.
	em := emitter.NewNoop()

	// Set up policy engine with default rules and configured stale threshold.
	defaultRules := []model.SeverityRule{
		{IsAuthorized: model.AuthorizationUnauthorized, IsManaged: model.ManagedUnmanaged, Severity: model.SeverityCritical},
		{IsAuthorized: model.AuthorizationUnauthorized, Severity: model.SeverityHigh},
		{IsManaged: model.ManagedUnmanaged, Severity: model.SeverityMedium},
	}
	pol := policy.New(defaultRules, cfg.StaleThresholdDuration())

	// Create and run the scan engine.
	eng := engine.New(st, registry, dd, cls, em, pol, met)

	result, err := eng.Run(ctx, cfg)

	// Graceful shutdown of metrics server (if started).
	if metricsSrv != nil {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = metricsSrv.Shutdown(shutCtx)
		shutCancel()
	}

	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Print scan summary to stderr.
	_, _ = fmt.Fprintf(os.Stderr, "\nScan complete: %d total, %d new, %d updated, %d stale, %d events, %d software (%d errors)\n",
		result.TotalAssets, result.NewAssets, result.UpdatedAssets,
		result.StaleAssets, result.EventsEmitted,
		result.SoftwareCount, result.SoftwareErrors)

	// Output asset list with software.
	assets, err := st.ListAssets(ctx, store.AssetFilter{})
	if err != nil {
		return fmt.Errorf("list assets: %w", err)
	}

	type assetWithSoftware struct {
		Software []model.InstalledSoftware `json:"software,omitempty"`
		model.Asset
	}

	enriched := make([]assetWithSoftware, 0, len(assets))
	for _, a := range assets {
		entry := assetWithSoftware{Asset: a}
		sw, swErr := st.ListSoftware(ctx, a.ID)
		if swErr == nil && len(sw) > 0 {
			entry.Software = sw
		}
		enriched = append(enriched, entry)
	}

	switch strings.ToLower(output) {
	case "json":
		return formatJSON(enriched)
	case "csv":
		formatCSV(assets)
	default:
		formatTable(assets)
	}

	return nil
}

// ---------------------------------------------------------------------------
// diff command
// ---------------------------------------------------------------------------

func newDiffCmd() *cobra.Command {
	var (
		output        string
		showUnchanged bool
	)

	cmd := &cobra.Command{
		Use:   "diff <db1> <db2>",
		Short: "Compare two scan databases",
		Long: `Open two SQLite databases produced by previous scans and compare their
asset inventories. Assets are matched by their natural key (hostname + asset_type).
The output shows new, removed, changed, and optionally unchanged assets.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(args[0], args[1], output, showUnchanged)
		},
	}

	cmd.Flags().StringVar(&output, "output", "table", "output format: json, csv, table")
	cmd.Flags().BoolVar(&showUnchanged, "show-unchanged", false, "include unchanged assets in output")

	return cmd
}

func runDiff(db1Path, db2Path, output string, showUnchanged bool) error {
	ctx := context.Background()

	// Open both databases.
	st1, err := sqlite.New(db1Path)
	if err != nil {
		return fmt.Errorf("open db1 %s: %w", db1Path, err)
	}
	defer func() { _ = st1.Close() }()

	st2, err := sqlite.New(db2Path)
	if err != nil {
		return fmt.Errorf("open db2 %s: %w", db2Path, err)
	}
	defer func() { _ = st2.Close() }()

	assets1, err := st1.ListAssets(ctx, store.AssetFilter{})
	if err != nil {
		return fmt.Errorf("list assets db1: %w", err)
	}

	assets2, err := st2.ListAssets(ctx, store.AssetFilter{})
	if err != nil {
		return fmt.Errorf("list assets db2: %w", err)
	}

	result := computeDiff(assets1, assets2)

	switch strings.ToLower(output) {
	case "json":
		return formatDiffJSON(result, showUnchanged)
	case "csv":
		formatDiffCSV(result, showUnchanged)
	default:
		formatDiffTable(result, showUnchanged)
	}

	return nil
}

// naturalKey builds a comparison key from hostname and asset type.
func naturalKey(a model.Asset) string {
	return a.Hostname + "|" + string(a.AssetType)
}

// computeDiff compares two asset slices by natural key.
func computeDiff(before, after []model.Asset) DiffResult {
	beforeMap := make(map[string]model.Asset, len(before))
	for _, a := range before {
		beforeMap[naturalKey(a)] = a
	}

	afterMap := make(map[string]model.Asset, len(after))
	for _, a := range after {
		afterMap[naturalKey(a)] = a
	}

	var result DiffResult

	// Check for new and changed assets.
	for key, a2 := range afterMap {
		a1, exists := beforeMap[key]
		if !exists {
			result.New = append(result.New, a2)
			continue
		}
		fields := compareAssets(a1, a2)
		if len(fields) > 0 {
			result.Changed = append(result.Changed, ChangedAsset{
				Before: a1,
				After:  a2,
				Fields: fields,
			})
		} else {
			result.Unchanged = append(result.Unchanged, a2)
		}
	}

	// Check for removed assets.
	for key, a1 := range beforeMap {
		if _, exists := afterMap[key]; !exists {
			result.Removed = append(result.Removed, a1)
		}
	}

	return result
}

// compareAssets returns the names of fields that differ between two assets.
func compareAssets(a, b model.Asset) []string {
	var fields []string
	if !a.LastSeenAt.Equal(b.LastSeenAt) {
		fields = append(fields, "LastSeenAt")
	}
	if a.IsAuthorized != b.IsAuthorized {
		fields = append(fields, "IsAuthorized")
	}
	if a.IsManaged != b.IsManaged {
		fields = append(fields, "IsManaged")
	}
	if a.OSVersion != b.OSVersion {
		fields = append(fields, "OSVersion")
	}
	if a.OSFamily != b.OSFamily {
		fields = append(fields, "OSFamily")
	}
	if a.Environment != b.Environment {
		fields = append(fields, "Environment")
	}
	if a.Owner != b.Owner {
		fields = append(fields, "Owner")
	}
	if a.DiscoverySource != b.DiscoverySource {
		fields = append(fields, "DiscoverySource")
	}
	return fields
}

// ---------------------------------------------------------------------------
// Diff output formatters
// ---------------------------------------------------------------------------

func formatDiffJSON(result DiffResult, showUnchanged bool) error {
	out := map[string]any{
		"summary": map[string]int{
			"new":       len(result.New),
			"removed":   len(result.Removed),
			"changed":   len(result.Changed),
			"unchanged": len(result.Unchanged),
		},
		"new":     result.New,
		"removed": result.Removed,
		"changed": result.Changed,
	}
	if showUnchanged {
		out["unchanged"] = result.Unchanged
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func formatDiffTable(result DiffResult, showUnchanged bool) {
	fmt.Printf("Diff Summary\n")
	fmt.Printf("  New:       %d\n", len(result.New))
	fmt.Printf("  Removed:   %d\n", len(result.Removed))
	fmt.Printf("  Changed:   %d\n", len(result.Changed))
	fmt.Printf("  Unchanged: %d\n\n", len(result.Unchanged))

	if len(result.New) > 0 {
		fmt.Println("--- New Assets ---")
		formatTable(result.New)
		fmt.Println()
	}

	if len(result.Removed) > 0 {
		fmt.Println("--- Removed Assets ---")
		formatTable(result.Removed)
		fmt.Println()
	}

	if len(result.Changed) > 0 {
		fmt.Println("--- Changed Assets ---")
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "HOSTNAME\tTYPE\tCHANGED FIELDS")
		for _, c := range result.Changed {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n",
				c.After.Hostname,
				c.After.AssetType,
				strings.Join(c.Fields, ", "),
			)
		}
		_ = w.Flush()
		fmt.Println()
	}

	if showUnchanged && len(result.Unchanged) > 0 {
		fmt.Println("--- Unchanged Assets ---")
		formatTable(result.Unchanged)
		fmt.Println()
	}
}

func formatDiffCSV(result DiffResult, showUnchanged bool) {
	w := csv.NewWriter(os.Stdout)
	defer w.Flush()

	_ = w.Write([]string{"status", "hostname", "asset_type", "is_authorized", "is_managed", "os_version", "changed_fields"})

	for _, a := range result.New {
		_ = w.Write([]string{"new", a.Hostname, string(a.AssetType), string(a.IsAuthorized), string(a.IsManaged), a.OSVersion, ""})
	}
	for _, a := range result.Removed {
		_ = w.Write([]string{"removed", a.Hostname, string(a.AssetType), string(a.IsAuthorized), string(a.IsManaged), a.OSVersion, ""})
	}
	for _, c := range result.Changed {
		_ = w.Write([]string{"changed", c.After.Hostname, string(c.After.AssetType), string(c.After.IsAuthorized), string(c.After.IsManaged), c.After.OSVersion, strings.Join(c.Fields, ";")})
	}
	if showUnchanged {
		for _, a := range result.Unchanged {
			_ = w.Write([]string{"unchanged", a.Hostname, string(a.AssetType), string(a.IsAuthorized), string(a.IsManaged), a.OSVersion, ""})
		}
	}
}

// ---------------------------------------------------------------------------
// discover-services command
// ---------------------------------------------------------------------------

func newDiscoverServicesCmd() *cobra.Command {
	var (
		output  string
		verbose bool
	)

	cmd := &cobra.Command{
		Use:   "discover-services",
		Short: "Detect reachable infrastructure APIs",
		Long: `Probe the local machine and network gateway for known infrastructure services
(Docker, Wazuh, Proxmox, ClickHouse, etc.) and report what was found. This
helps identify which discovery sources can be enabled without manual
configuration.

All probes are read-only: no credentials are sent, no data is written.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiscoverServices(output, verbose)
		},
	}

	cmd.Flags().StringVar(&output, "output", "table", "output format: json, table")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable debug logging")

	return cmd
}

func runDiscoverServices(output string, verbose bool) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logLevel := slog.LevelWarn
	if verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	discovered := autodiscovery.Run(ctx, autodiscovery.Options{})

	switch strings.ToLower(output) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(discovered)
	default:
		formatDiscoveredServices(discovered)
	}

	return nil
}

func formatDiscoveredServices(services []autodiscovery.DiscoveredService) {
	fmt.Println()
	fmt.Println("Infrastructure Auto-Discovery")
	fmt.Println("==============================")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "  SERVICE\tENDPOINT\tSTATUS")
	for _, svc := range services {
		_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\n", svc.Name, svc.Endpoint, svc.Status)
	}
	_ = w.Flush()

	ready := 0
	needsCreds := 0
	for _, svc := range services {
		switch svc.Status {
		case "ready":
			ready++
		case "needs_credentials":
			needsCreds++
		}
	}
	fmt.Printf("\n  Ready: %d | Need credentials: %d\n", ready, needsCreds)

	// Print setup hints for services that need credentials.
	// Uses OS-aware env set commands (export / set / $env:).
	hasHints := false
	for _, svc := range services {
		if svc.Status == "needs_credentials" && len(svc.Credentials) > 0 {
			if !hasHints {
				fmt.Println()
				fmt.Println("  To enable all discovered services:")
				fmt.Println()
				hasHints = true
			}
			fmt.Printf("    # %s\n", svc.DisplayName)
			for _, env := range svc.Credentials {
				fmt.Printf("    %s\n", osutil.EnvSetCommand(env, "..."))
			}
			fmt.Println()
		}
	}

	if ready > 0 {
		fmt.Println("  Then run: kite-collector scan --auto")
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// agent command (streaming mode)
// ---------------------------------------------------------------------------

func newAgentCmd() *cobra.Command {
	var (
		stream   bool
		interval string
		cfgFile  string
		dbPath   string
		verbose  bool
	)

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run continuous asset discovery agent",
		Long: `Start a long-running agent that performs periodic scan cycles and emits
OTLP events to the configured collector endpoint. Use --stream to enable
continuous mode with a configurable scan interval.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAgent(cfgFile, dbPath, interval, verbose, stream)
		},
	}

	cmd.Flags().BoolVar(&stream, "stream", false, "enable continuous streaming mode")
	cmd.Flags().StringVar(&interval, "interval", "", "scan interval (overrides config, e.g. 6h)")
	cmd.Flags().StringVar(&cfgFile, "config", "kite-collector.yaml", "path to configuration file")
	cmd.Flags().StringVar(&dbPath, "db", "kite.db", "path to SQLite database")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable debug logging")

	return cmd
}

func runAgent(cfgFile, dbPath, interval string, verbose, stream bool) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var cfg *config.Config
	if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
		c, loadErr := config.Load("")
		if loadErr != nil {
			return fmt.Errorf("load default config: %w", loadErr)
		}
		cfg = c
	} else {
		c, loadErr := config.Load(cfgFile)
		if loadErr != nil {
			return fmt.Errorf("load config %s: %w", cfgFile, loadErr)
		}
		cfg = c
	}

	// Validate configuration early.
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config validation: %w", err)
	}

	logLevel := slog.LevelInfo
	if verbose || strings.EqualFold(cfg.LogLevel, "debug") {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	// Select store backend: PostgreSQL if DSN is configured, otherwise SQLite.
	var st store.Store
	if cfg.Postgres.DSN != "" {
		slog.Info("agent: using PostgreSQL backend")
		pgStore, pgErr := postgres.New(cfg.Postgres.DSN)
		if pgErr != nil {
			return fmt.Errorf("open postgres store: %w", pgErr)
		}
		defer func() { _ = pgStore.Close() }()
		if pgErr = pgStore.Migrate(ctx); pgErr != nil {
			return fmt.Errorf("migrate postgres store: %w", pgErr)
		}
		st = pgStore
	} else {
		slog.Info("agent: using SQLite backend", "path", dbPath)
		dataDir := filepath.Dir(dbPath)
		if mkErr := os.MkdirAll(dataDir, 0o750); mkErr != nil {
			return fmt.Errorf("create data dir %s: %w", dataDir, mkErr)
		}
		sqliteStore, sqlErr := sqlite.New(dbPath)
		if sqlErr != nil {
			return fmt.Errorf("open sqlite store: %w", sqlErr)
		}
		defer func() { _ = sqliteStore.Close() }()
		if sqlErr = sqliteStore.Migrate(ctx); sqlErr != nil {
			return fmt.Errorf("migrate sqlite store: %w", sqlErr)
		}
		st = sqliteStore
	}

	registry := discovery.NewRegistry()
	registry.Register(network.New())
	registry.Register(agent.New())
	registry.Register(cloud.NewAWS())
	registry.Register(cloud.NewGCP())
	registry.Register(cloud.NewAzure())
	registry.Register(mdm.NewJamf())
	registry.Register(mdm.NewIntune())
	registry.Register(mdm.NewSCCM())
	registry.Register(cmdb.NewServiceNow())
	registry.Register(cmdb.NewNetBox())
	registry.Register(dockerdisc.New())
	registry.Register(unifi.New())
	registry.Register(proxmox.New())
	registry.Register(snmp.New())
	registry.Register(vps.NewHetzner())
	registry.Register(vps.NewDigitalOcean())
	registry.Register(vps.NewVultr())
	registry.Register(vps.NewHostinger())
	registry.Register(vps.NewLinode())
	registry.Register(vps.NewScaleway())
	registry.Register(vps.NewOVHcloud())
	registry.Register(vps.NewUpCloud())
	registry.Register(vps.NewKamatera())
	registry.Register(wazuhdisc.New())

	met := metrics.New()
	var metricsSrv *http.Server
	if cfg.Metrics.Enabled {
		listen := cfg.Metrics.Listen
		if listen == "" {
			listen = ":9090"
		}
		metricsSrv = met.Serve(listen)
	}

	dd := dedup.New(st, met)

	authorizer, err := classifier.NewAuthorizer(
		cfg.Classification.Authorization.AllowlistFile,
		cfg.Classification.Authorization.MatchFields,
	)
	if err != nil {
		return fmt.Errorf("create authorizer: %w", err)
	}
	manager := classifier.NewManager(cfg.Classification.Managed.RequiredControls)
	cls := classifier.New(authorizer, manager)

	// Set up OTLP emitter if endpoint is configured, otherwise noop.
	var em emitter.Emitter
	if cfg.Streaming.OTLP.Endpoint != "" {
		otlpCfg := emitter.OTLPConfig{
			Endpoint: cfg.Streaming.OTLP.Endpoint,
			Protocol: cfg.Streaming.OTLP.Protocol,
			TLS: emitter.TLSConfig{
				Enabled:  cfg.Streaming.OTLP.TLS.Enabled,
				CertFile: cfg.Streaming.OTLP.TLS.CertFile,
				KeyFile:  cfg.Streaming.OTLP.TLS.KeyFile,
				CAFile:   cfg.Streaming.OTLP.TLS.CAFile,
			},
		}
		otlpEmitter, otlpErr := emitter.NewOTLP(otlpCfg, version)
		if otlpErr != nil {
			return fmt.Errorf("create OTLP emitter: %w", otlpErr)
		}
		em = otlpEmitter
		defer func() { _ = otlpEmitter.Shutdown(context.Background()) }()
	} else {
		em = emitter.NewNoop()
	}

	defaultRules := []model.SeverityRule{
		{IsAuthorized: model.AuthorizationUnauthorized, IsManaged: model.ManagedUnmanaged, Severity: model.SeverityCritical},
		{IsAuthorized: model.AuthorizationUnauthorized, Severity: model.SeverityHigh},
		{IsManaged: model.ManagedUnmanaged, Severity: model.SeverityMedium},
	}
	pol := policy.New(defaultRules, cfg.StaleThresholdDuration())

	eng := engine.New(st, registry, dd, cls, em, pol, met)

	// Start REST API in background.
	apiHandler := rest.New(st, logger)
	apiMux := apiHandler.Mux()
	apiMux.Handle("/metrics", met.Handler())

	apiAddr := ":8080"
	apiSrv := &http.Server{
		Addr:              apiAddr,
		Handler:           apiMux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		slog.Info("starting REST API server", "addr", apiAddr)
		if srvErr := apiSrv.ListenAndServe(); srvErr != nil && srvErr != http.ErrServerClosed {
			slog.Error("REST API server error", "error", srvErr)
		}
	}()

	if !stream {
		// One-shot mode via agent command (no --stream flag).
		result, scanErr := eng.Run(ctx, cfg)
		if scanErr != nil {
			return fmt.Errorf("agent scan failed: %w", scanErr)
		}
		_, _ = fmt.Fprintf(os.Stderr, "Agent scan complete: %d total, %d new, %d updated, %d stale\n",
			result.TotalAssets, result.NewAssets, result.UpdatedAssets, result.StaleAssets)
		return nil
	}

	// Continuous streaming mode.
	scanInterval := cfg.StreamingInterval()
	if interval != "" {
		if d, parseErr := time.ParseDuration(interval); parseErr == nil {
			scanInterval = d
		}
	}

	slog.Info("agent: starting streaming mode", "interval", scanInterval)

	// Run initial scan immediately.
	if result, scanErr := eng.Run(ctx, cfg); scanErr != nil {
		slog.Error("agent: initial scan failed", "error", scanErr)
	} else {
		slog.Info("agent: initial scan complete",
			"total", result.TotalAssets,
			"new", result.NewAssets,
		)
	}

	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("agent: shutting down")
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = apiSrv.Shutdown(shutdownCtx)
			if metricsSrv != nil {
				_ = metricsSrv.Shutdown(shutdownCtx)
			}
			_ = em.Shutdown(shutdownCtx)
			return nil
		case <-ticker.C:
			if result, scanErr := eng.Run(ctx, cfg); scanErr != nil {
				slog.Error("agent: scan failed", "error", scanErr)
			} else {
				slog.Info("agent: scan complete",
					"total", result.TotalAssets,
					"new", result.NewAssets,
					"updated", result.UpdatedAssets,
					"stale", result.StaleAssets,
				)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// report command
// ---------------------------------------------------------------------------

func newReportCmd() *cobra.Command {
	var (
		dbPath string
		format string
		output string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate asset inventory report",
		Long: `Read the SQLite database and produce a report in the requested format.
Supported formats: json, csv, table, html.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReport(dbPath, format, output)
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "./kite.db", "path to SQLite database")
	cmd.Flags().StringVar(&format, "format", "table", "report format: json, csv, table, html")
	cmd.Flags().StringVar(&output, "output", "", "output file path (default: stdout)")

	return cmd
}

func runReport(dbPath, format, outputPath string) error {
	ctx := context.Background()

	st, err := sqlite.New(dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = st.Close() }()

	assets, err := st.ListAssets(ctx, store.AssetFilter{})
	if err != nil {
		return fmt.Errorf("list assets: %w", err)
	}

	latestRun, _ := st.GetLatestScanRun(ctx)

	// If an output file is requested, redirect stdout.
	if outputPath != "" {
		f, fErr := os.Create(outputPath) //#nosec G304 -- path from trusted CLI flag
		if fErr != nil {
			return fmt.Errorf("create output file: %w", fErr)
		}
		defer func() { _ = f.Close() }()
		os.Stdout = f
	}

	// Collect findings and posture assessments for the report.
	allFindings, _ := st.ListFindings(ctx, store.FindingFilter{})
	allPosture, _ := st.ListPostureAssessments(ctx, store.PostureFilter{})

	switch strings.ToLower(format) {
	case "json":
		report := map[string]any{
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"total_assets": len(assets),
			"assets":       assets,
		}
		if latestRun != nil {
			report["latest_scan"] = latestRun
		}
		if len(allFindings) > 0 {
			report["findings"] = allFindings
			report["total_findings"] = len(allFindings)
		}
		if len(allPosture) > 0 {
			report["posture_assessments"] = allPosture
			report["total_posture"] = len(allPosture)
		}
		return formatJSON(report)
	case "csv":
		formatCSV(assets)
	case "html":
		return formatHTMLReport(ctx, st, assets, latestRun)
	default:
		if latestRun != nil {
			fmt.Printf("Latest scan: %s (total: %d, new: %d, stale: %d)\n\n",
				latestRun.StartedAt.Format(time.RFC3339),
				latestRun.TotalAssets,
				latestRun.NewAssets,
				latestRun.StaleAssets,
			)
		}
		formatTable(assets)
	}

	return nil
}

// ---------------------------------------------------------------------------
// init command
// ---------------------------------------------------------------------------

func newInitCmd() *cobra.Command {
	var (
		output  string
		verbose bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Interactive setup wizard",
		Long: `Run infrastructure auto-discovery, prompt for missing credentials
interactively, and generate a configuration file.

The wizard detects available services (Docker, Wazuh, UniFi, Proxmox, etc.),
asks for credentials when needed, and writes a ready-to-use config file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(output, verbose)
		},
	}

	cmd.Flags().StringVar(&output, "output", ".", "directory to write the config file")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable debug logging")

	return cmd
}

func runInit(outputDir string, verbose bool) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if verbose {
		logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
		slog.SetDefault(logger)
	}

	fmt.Println()
	fmt.Println("  Kite-Collector Setup")
	fmt.Println("  ====================")
	fmt.Println()
	fmt.Println("  Scanning for infrastructure services...")
	fmt.Println()

	discovered := autodiscovery.Run(ctx, autodiscovery.Options{})

	fmt.Println("  Found:")
	for _, svc := range discovered {
		status := svc.Status
		icon := "?"
		switch status {
		case "ready":
			icon = "+"
		case "needs_credentials":
			icon = "!"
		}
		fmt.Printf("    [%s] %-16s %-40s %s\n", icon, svc.DisplayName, svc.Endpoint, status)
	}
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)

	// Prompt for credentials for services that need them.
	credentials := make(map[string]string)
	for _, svc := range discovered {
		if svc.Status != "needs_credentials" || len(svc.Credentials) == 0 {
			continue
		}
		fmt.Printf("  Configure %s:\n", svc.DisplayName)
		for _, env := range svc.Credentials {
			label := env
			fmt.Printf("    %s: ", label)
			if scanner.Scan() {
				val := strings.TrimSpace(scanner.Text())
				if val != "" {
					credentials[env] = val
				}
			}
		}
		fmt.Println()
	}

	// Build config YAML.
	var cfgBuf strings.Builder
	cfgBuf.WriteString("# kite-collector configuration\n")
	cfgBuf.WriteString("# Generated by: kite-collector init\n\n")
	cfgBuf.WriteString("discovery:\n")
	cfgBuf.WriteString("  sources:\n")
	cfgBuf.WriteString("    agent:\n")
	cfgBuf.WriteString("      enabled: true\n")
	cfgBuf.WriteString("      collect_software: true\n")

	for _, svc := range discovered {
		if svc.Status == "ready" || (svc.Status == "needs_credentials" && hasAllCreds(svc.Credentials, credentials)) {
			fmt.Fprintf(&cfgBuf, "    %s:\n", svc.Name)
			cfgBuf.WriteString("      enabled: true\n")
			if svc.Endpoint != "" {
				fmt.Fprintf(&cfgBuf, "      endpoint: %s\n", svc.Endpoint)
			}
		}
	}

	cfgBuf.WriteString("\naudit:\n  enabled: true\n")
	cfgBuf.WriteString("\nstale_threshold: 168h\n")

	cfgPath := filepath.Join(outputDir, "kite-collector.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgBuf.String()), 0o640); err != nil { //#nosec G306 -- config file with restricted permissions
		return fmt.Errorf("write config: %w", err)
	}

	fmt.Printf("  Config saved to %s\n\n", cfgPath)

	// Print env vars that need to be set.
	if len(credentials) > 0 {
		fmt.Println("  Set these environment variables before scanning:")
		fmt.Println()
		for env, val := range credentials {
			fmt.Printf("    %s\n", osutil.EnvSetCommand(env, val))
		}
		fmt.Println()
	}

	fmt.Println("  Run your first scan:")
	fmt.Printf("    kite-collector scan --config %s\n\n", cfgPath)
	fmt.Println("  Or scan with auto-discovery:")
	fmt.Println("    kite-collector scan --auto")
	fmt.Println()

	return nil
}

// hasAllCreds checks if all required credential env vars have values.
func hasAllCreds(required []string, provided map[string]string) bool {
	for _, env := range required {
		if _, ok := provided[env]; !ok {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// query command
// ---------------------------------------------------------------------------

func newQueryCmd() *cobra.Command {
	var (
		dbPath   string
		limit    int
		severity string
	)

	cmd := &cobra.Command{
		Use:   "query <target>",
		Short: "Query the SQLite database",
		Long: `Run a human-friendly query against the kite-collector SQLite database.

Targets:
  assets     List discovered assets
  software   List installed software packages
  findings   List configuration findings
  scans      List scan history`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"assets", "software", "findings", "scans"},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runQuery(args[0], dbPath, limit, severity)
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "./kite.db", "path to SQLite database")
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum rows to return")
	cmd.Flags().StringVar(&severity, "severity", "", "filter findings by severity")

	return cmd
}

func runQuery(target, dbPath string, limit int, severity string) error {
	queries := map[string]string{
		"assets":   "SELECT hostname, asset_type, os_family, is_authorized, discovery_source, last_seen_at FROM assets ORDER BY last_seen_at DESC",
		"software": "SELECT software_name, version, package_manager, cpe23 FROM installed_software ORDER BY software_name",
		"findings": "SELECT check_id, severity, cwe_id, title FROM config_findings ORDER BY severity",
		"scans":    "SELECT started_at, status, total_assets, new_assets, stale_assets FROM scan_runs ORDER BY started_at DESC",
	}

	q, ok := queries[target]
	if !ok {
		return fmt.Errorf("unknown query target: %s (use: assets, software, findings, scans)", target)
	}

	if severity != "" && target == "findings" {
		q = "SELECT check_id, severity, cwe_id, title FROM config_findings WHERE severity = ? ORDER BY severity"
	}

	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}

	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	var rows *sql.Rows
	if severity != "" && target == "findings" {
		rows, err = db.QueryContext(ctx, q, severity) //#nosec G201 -- query is from static map, severity is parameterized
	} else {
		rows, err = db.QueryContext(ctx, q) //#nosec G201 -- query and limit are from static map and validated int
	}
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	cols, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("columns: %w", err)
	}

	// Print as formatted table.
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, strings.ToUpper(strings.Join(cols, "\t")))

	values := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range values {
		ptrs[i] = &values[i]
	}

	count := 0
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return fmt.Errorf("scan row: %w", err)
		}
		parts := make([]string, len(cols))
		for i, v := range values {
			if v == nil {
				parts[i] = ""
			} else {
				parts[i] = fmt.Sprintf("%v", v)
			}
		}
		_, _ = fmt.Fprintln(w, strings.Join(parts, "\t"))
		count++
	}

	_ = w.Flush()
	_, _ = fmt.Fprintf(os.Stderr, "\n%d rows\n", count)

	return rows.Err()
}

// ---------------------------------------------------------------------------
// db command
// ---------------------------------------------------------------------------

func newDBCmd() *cobra.Command {
	var dbPath string

	cmd := &cobra.Command{
		Use:   "db",
		Short: "Open SQLite shell with table formatting",
		Long: `Launch the sqlite3 CLI with human-friendly defaults (.mode table,
.headers on) pre-configured. Requires sqlite3 to be installed.

If sqlite3 is not installed, prints a help message instead.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDB(dbPath)
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "./kite.db", "path to SQLite database")

	return cmd
}

func runDB(dbPath string) error {
	sqlite3Path, err := exec.LookPath("sqlite3")
	if err != nil {
		fmt.Println("sqlite3 is not installed or not in PATH.")
		fmt.Println()
		switch runtime.GOOS {
		case "darwin":
			fmt.Println("  Install: brew install sqlite3")
		case "linux":
			fmt.Println("  Install: sudo apt install sqlite3  (Debian/Ubuntu)")
			fmt.Println("           sudo pacman -S sqlite     (Arch)")
			fmt.Println("           sudo dnf install sqlite   (Fedora/RHEL)")
		case "windows":
			fmt.Println("  Download from: https://www.sqlite.org/download.html")
		}
		fmt.Println()
		fmt.Println("  Or use: kite-collector query assets")
		return nil
	}

	// Create an init file for table mode.
	initSQL := ".mode table\n.headers on\n.prompt 'kite> ' '   > '\n"
	initFile, err := os.CreateTemp("", "kite-sqlite-init-*.sql")
	if err != nil {
		return fmt.Errorf("create init file: %w", err)
	}
	defer func() { _ = os.Remove(initFile.Name()) }()
	if _, err := initFile.WriteString(initSQL); err != nil {
		return fmt.Errorf("write init file: %w", err)
	}
	_ = initFile.Close()

	cmd := exec.CommandContext(context.Background(), sqlite3Path, "-init", initFile.Name(), dbPath) //#nosec G204 -- sqlite3Path from LookPath, dbPath from trusted CLI flag
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// ---------------------------------------------------------------------------
// error command
// ---------------------------------------------------------------------------

func newErrorCmd() *cobra.Command {
	var listAll bool

	cmd := &cobra.Command{
		Use:   "error [code]",
		Short: "Look up a kite-collector error code",
		Long: `Display detailed information about a kite-collector error code including
the cause and OS-specific remediation steps.

Example: kite-collector error KITE-E001`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if listAll {
				for _, code := range kiteerrors.Codes() {
					e := kiteerrors.Lookup(code)
					fmt.Printf("  %s  %s\n", e.Code, e.Message)
				}
				return nil
			}
			if len(args) == 0 {
				fmt.Println("Usage: kite-collector error <code>")
				fmt.Println()
				fmt.Println("Known error codes:")
				for _, code := range kiteerrors.Codes() {
					e := kiteerrors.Lookup(code)
					fmt.Printf("  %s  %s\n", e.Code, e.Message)
				}
				return nil
			}
			e := kiteerrors.Lookup(args[0])
			if e == nil {
				return fmt.Errorf("unknown error code: %s", args[0])
			}
			fmt.Print(e.Format())
			return nil
		},
	}

	cmd.Flags().BoolVar(&listAll, "list", false, "list all error codes")

	return cmd
}

// ---------------------------------------------------------------------------
// version command
// ---------------------------------------------------------------------------

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("kite-collector %s\n", version)
			fmt.Printf("  commit:  %s\n", commit)
			fmt.Printf("  built:   %s\n", date)
			fmt.Printf("  go:      %s\n", runtime.Version())
			fmt.Printf("  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
			n := sqlite.EmbeddedMigrationCount()
			fmt.Printf("  schema:  v%d (%d migrations embedded)\n", n, n)
		},
	}
}

// ---------------------------------------------------------------------------
// migrate command
// ---------------------------------------------------------------------------

func newMigrateCmd() *cobra.Command {
	var (
		dbPath string
		status bool
		repair string
		dryRun bool
	)

	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Run or inspect database migrations",
		Long: `Apply pending embedded SQL migrations to the SQLite database,
show migration status, or repair a failed migration entry.

Examples:
  kite-collector migrate                          # apply pending migrations
  kite-collector migrate --status                 # show applied/pending
  kite-collector migrate --dry-run                # show what would run
  kite-collector migrate --repair 20260405000000_config_findings  # allow re-apply`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMigrate(dbPath, status, repair, dryRun)
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "./kite.db", "path to SQLite database")
	cmd.Flags().BoolVar(&status, "status", false, "show applied and pending migrations")
	cmd.Flags().StringVar(&repair, "repair", "", "remove migration entry for re-application")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be applied without running")

	return cmd
}

func runMigrate(dbPath string, status bool, repair string, dryRun bool) error {
	ctx := context.Background()

	dataDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	st, err := sqlite.New(dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = st.Close() }()

	switch {
	case status:
		return showMigrationStatus(ctx, st, dbPath)
	case repair != "":
		return st.RepairMigration(ctx, repair)
	case dryRun:
		return showPendingMigrations(ctx, st)
	default:
		if mErr := st.Migrate(ctx); mErr != nil {
			return mErr
		}
		_, _ = fmt.Fprintln(os.Stderr, "all migrations applied")
		return nil
	}
}

func showMigrationStatus(ctx context.Context, st *sqlite.SQLiteStore, dbPath string) error {
	infos, err := st.MigrationStatus(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("\n  Migration Status (SQLite: %s)\n", dbPath)
	fmt.Printf("  %s\n", strings.Repeat("=", 60))
	fmt.Printf("  %-30s %-10s %s\n", "VERSION", "STATUS", "CHECKSUM")

	applied, pending := 0, 0
	for _, info := range infos {
		if info.Applied {
			fmt.Printf("  %-30s applied (%s)  %s\n",
				info.Version, info.AppliedAt, info.AppliedChecksum[:12])
			applied++
		} else {
			fmt.Printf("  %-30s pending       %s\n",
				info.Version, info.Checksum[:12])
			pending++
		}
	}

	fmt.Printf("\n  Applied: %d | Pending: %d\n\n", applied, pending)
	return nil
}

func showPendingMigrations(ctx context.Context, st *sqlite.SQLiteStore) error {
	infos, err := st.MigrationStatus(ctx)
	if err != nil {
		return err
	}

	pending := 0
	for _, info := range infos {
		if !info.Applied {
			fmt.Printf("  would apply: %s (%s)\n", info.Version, info.Checksum[:12])
			pending++
		}
	}

	if pending == 0 {
		fmt.Println("  all migrations already applied")
	} else {
		fmt.Printf("\n  %d migration(s) would be applied\n", pending)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Output formatting helpers
// ---------------------------------------------------------------------------

// formatJSON marshals v as indented JSON and writes it to stdout.
func formatJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// formatTable renders assets as a human-readable table.
func formatTable(assets []model.Asset) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "HOSTNAME\tTYPE\tOS\tAUTHORIZED\tMANAGED\tSOURCE\tLAST SEEN")
	for _, a := range assets {
		osInfo := a.OSFamily
		if a.OSVersion != "" {
			osInfo = a.OSVersion
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			a.Hostname,
			a.AssetType,
			osInfo,
			a.IsAuthorized,
			a.IsManaged,
			a.DiscoverySource,
			a.LastSeenAt.Format("2006-01-02T15:04:05Z"),
		)
	}
	_ = w.Flush()
}

// formatCSV writes assets as CSV to stdout.
func formatCSV(assets []model.Asset) {
	w := csv.NewWriter(os.Stdout)
	defer w.Flush()

	_ = w.Write([]string{
		"id", "hostname", "asset_type", "os_family", "os_version",
		"is_authorized", "is_managed", "environment", "owner",
		"discovery_source", "first_seen_at", "last_seen_at",
	})

	for _, a := range assets {
		_ = w.Write([]string{
			a.ID.String(),
			a.Hostname,
			string(a.AssetType),
			a.OSFamily,
			a.OSVersion,
			string(a.IsAuthorized),
			string(a.IsManaged),
			a.Environment,
			a.Owner,
			a.DiscoverySource,
			a.FirstSeenAt.Format("2006-01-02T15:04:05Z"),
			a.LastSeenAt.Format("2006-01-02T15:04:05Z"),
		})
	}
}

// ---------------------------------------------------------------------------
// HTML compliance report
// ---------------------------------------------------------------------------

// htmlReportData holds all data rendered by the HTML compliance template.
type htmlReportData struct {
	EventSummary      map[string]int
	LatestScan        *model.ScanRun
	GeneratedAt       string
	Version           string
	Assets            []model.Asset
	Frameworks        []complianceFramework
	TotalAssets       int
	NewAssets         int
	UpdatedAssets     int
	StaleAssets       int
	AuthorizedCount   int
	UnauthorizedCount int
	AuthUnknownCount  int
	ManagedCount      int
	UnmanagedCount    int
	MgmtUnknownCount  int
}

// complianceFramework describes compliance alignment for a single framework.
type complianceFramework struct {
	Name        string
	Control     string
	Description string
	Status      string // "Aligned", "Partial", "Not Aligned"
}

// assessCompliance evaluates compliance alignment based on the current asset
// inventory state. A framework is "Aligned" when the inventory has full
// coverage of classification and management data, "Partial" when some data
// is missing, and "Not Aligned" when the inventory is empty.
func assessCompliance(data *htmlReportData) []complianceFramework {
	// Compute a simple coverage score: fraction of assets that are both
	// classified (authorized/unauthorized) and managed/unmanaged.
	classifiedCount := data.AuthorizedCount + data.UnauthorizedCount
	managedClassified := data.ManagedCount + data.UnmanagedCount

	cisStatus := "Not Aligned"
	nistStatus := "Not Aligned"
	isoStatus := "Not Aligned"

	if data.TotalAssets > 0 {
		classifiedRatio := float64(classifiedCount) / float64(data.TotalAssets)
		managedRatio := float64(managedClassified) / float64(data.TotalAssets)

		if classifiedRatio >= 0.9 {
			cisStatus = "Aligned"
		} else if classifiedRatio > 0 {
			cisStatus = "Partial"
		}

		if classifiedRatio >= 0.9 && managedRatio >= 0.9 {
			nistStatus = "Aligned"
		} else if classifiedRatio > 0 || managedRatio > 0 {
			nistStatus = "Partial"
		}

		if classifiedRatio >= 0.9 && managedRatio >= 0.9 && data.UnauthorizedCount == 0 {
			isoStatus = "Aligned"
		} else if classifiedRatio > 0 || managedRatio > 0 {
			isoStatus = "Partial"
		}
	}

	return []complianceFramework{
		{
			Name:        "CIS Control 1",
			Control:     "Enterprise Asset Inventory",
			Description: "Actively manage all enterprise assets connected to the infrastructure",
			Status:      cisStatus,
		},
		{
			Name:        "NIST SP 1800-5",
			Control:     "IT Asset Management",
			Description: "Identify, track, and manage IT assets throughout their lifecycle",
			Status:      nistStatus,
		},
		{
			Name:        "ISO 27001 A.8",
			Control:     "Asset Management",
			Description: "Identify organizational assets and define appropriate protection responsibilities",
			Status:      isoStatus,
		},
	}
}

// formatHTMLReport generates a self-contained HTML compliance report.
func formatHTMLReport(ctx context.Context, st store.Store, assets []model.Asset, latestRun *model.ScanRun) error {
	// Query events for the event summary breakdown.
	events, err := st.ListEvents(ctx, store.EventFilter{Limit: 10000})
	if err != nil {
		return fmt.Errorf("list events for report: %w", err)
	}

	// Build classification counts.
	var authCount, unauthCount, authUnk int
	var mgdCount, unmgdCount, mgdUnk int
	for _, a := range assets {
		switch a.IsAuthorized {
		case model.AuthorizationAuthorized:
			authCount++
		case model.AuthorizationUnauthorized:
			unauthCount++
		case model.AuthorizationUnknown:
			authUnk++
		}
		switch a.IsManaged {
		case model.ManagedManaged:
			mgdCount++
		case model.ManagedUnmanaged:
			unmgdCount++
		case model.ManagedUnknown:
			mgdUnk++
		}
	}

	// Build event type counts.
	eventSummary := make(map[string]int)
	for _, ev := range events {
		eventSummary[string(ev.EventType)]++
	}

	data := htmlReportData{
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
		Version:           version,
		TotalAssets:       len(assets),
		AuthorizedCount:   authCount,
		UnauthorizedCount: unauthCount,
		AuthUnknownCount:  authUnk,
		ManagedCount:      mgdCount,
		UnmanagedCount:    unmgdCount,
		MgmtUnknownCount: mgdUnk,
		Assets:            assets,
		EventSummary:      eventSummary,
		LatestScan:        latestRun,
	}

	if latestRun != nil {
		data.NewAssets = latestRun.NewAssets
		data.UpdatedAssets = latestRun.UpdatedAssets
		data.StaleAssets = latestRun.StaleAssets
	}

	data.Frameworks = assessCompliance(&data)

	tmpl, err := template.New("report").Parse(htmlReportTemplate)
	if err != nil {
		return fmt.Errorf("parse HTML template: %w", err)
	}

	return tmpl.Execute(os.Stdout, data)
}

// htmlReportTemplate is the self-contained HTML compliance report template.
// It uses only inline CSS and no external resources.
const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kite Collector - Asset Compliance Report</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    margin: 0; padding: 0; background: #f4f6f9; color: #1a1a2e;
    line-height: 1.6;
  }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  header {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    color: #fff; padding: 32px 24px; margin-bottom: 24px; border-radius: 8px;
  }
  header h1 { margin: 0 0 8px 0; font-size: 1.75rem; }
  header p { margin: 0; opacity: 0.85; font-size: 0.9rem; }
  .meta-row { display: flex; gap: 24px; flex-wrap: wrap; margin-top: 12px; }
  .meta-item { font-size: 0.85rem; opacity: 0.75; }
  .summary-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px; margin-bottom: 24px;
  }
  .stat-card {
    background: #fff; border-radius: 8px; padding: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08); text-align: center;
  }
  .stat-card .value { font-size: 2rem; font-weight: 700; color: #1a1a2e; }
  .stat-card .label { font-size: 0.8rem; text-transform: uppercase; color: #666; letter-spacing: 0.5px; }
  section { background: #fff; border-radius: 8px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
  section h2 { margin-top: 0; font-size: 1.25rem; border-bottom: 2px solid #e0e0e0; padding-bottom: 8px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
  th { background: #f0f2f5; text-align: left; padding: 10px 12px; font-weight: 600; border-bottom: 2px solid #ddd; }
  td { padding: 8px 12px; border-bottom: 1px solid #eee; }
  tr:nth-child(even) td { background: #fafbfc; }
  tr:hover td { background: #f0f4ff; }
  .badge {
    display: inline-block; padding: 2px 10px; border-radius: 12px;
    font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
  }
  .badge-green { background: #d4edda; color: #155724; }
  .badge-red { background: #f8d7da; color: #721c24; }
  .badge-yellow { background: #fff3cd; color: #856404; }
  .badge-blue { background: #d1ecf1; color: #0c5460; }
  .badge-gray { background: #e2e3e5; color: #383d41; }
  .compliance-status { font-weight: 600; }
  .status-aligned { color: #155724; }
  .status-partial { color: #856404; }
  .status-not-aligned { color: #721c24; }
  .classification-grid {
    display: grid; grid-template-columns: 1fr 1fr; gap: 24px;
  }
  @media (max-width: 640px) {
    .classification-grid { grid-template-columns: 1fr; }
    .summary-grid { grid-template-columns: repeat(2, 1fr); }
  }
  .bar-container { display: flex; height: 24px; border-radius: 4px; overflow: hidden; margin: 8px 0; }
  .bar-segment { display: flex; align-items: center; justify-content: center; font-size: 0.7rem; font-weight: 600; color: #fff; min-width: 2px; }
  .bar-green { background: #28a745; }
  .bar-red { background: #dc3545; }
  .bar-yellow { background: #ffc107; color: #333; }
  footer { text-align: center; padding: 16px; font-size: 0.8rem; color: #999; }
</style>
</head>
<body>
<div class="container">

<header>
  <h1>Asset Compliance Report</h1>
  <p>Kite Collector - Enterprise Asset Inventory and Compliance Assessment</p>
  <div class="meta-row">
    <span class="meta-item">Generated: {{.GeneratedAt}}</span>
    <span class="meta-item">Version: {{.Version}}</span>
    {{- if .LatestScan}}
    <span class="meta-item">Latest Scan: {{.LatestScan.StartedAt.Format "2006-01-02T15:04:05Z"}} ({{.LatestScan.Status}})</span>
    {{- end}}
  </div>
</header>

<div class="summary-grid">
  <div class="stat-card">
    <div class="value">{{.TotalAssets}}</div>
    <div class="label">Total Assets</div>
  </div>
  <div class="stat-card">
    <div class="value">{{.NewAssets}}</div>
    <div class="label">New Assets</div>
  </div>
  <div class="stat-card">
    <div class="value">{{.UpdatedAssets}}</div>
    <div class="label">Updated Assets</div>
  </div>
  <div class="stat-card">
    <div class="value">{{.StaleAssets}}</div>
    <div class="label">Stale Assets</div>
  </div>
  <div class="stat-card">
    <div class="value">{{.AuthorizedCount}}</div>
    <div class="label">Authorized</div>
  </div>
  <div class="stat-card">
    <div class="value">{{.UnauthorizedCount}}</div>
    <div class="label">Unauthorized</div>
  </div>
</div>

<section>
  <h2>Compliance Summary</h2>
  <table>
    <thead>
      <tr>
        <th>Framework</th>
        <th>Control</th>
        <th>Description</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>
    {{range .Frameworks}}
      <tr>
        <td><strong>{{.Name}}</strong></td>
        <td>{{.Control}}</td>
        <td>{{.Description}}</td>
        <td>
          {{if eq .Status "Aligned"}}<span class="badge badge-green">Aligned</span>
          {{else if eq .Status "Partial"}}<span class="badge badge-yellow">Partial</span>
          {{else}}<span class="badge badge-red">Not Aligned</span>
          {{end}}
        </td>
      </tr>
    {{end}}
    </tbody>
  </table>
</section>

<section>
  <h2>Classification Breakdown</h2>
  <div class="classification-grid">
    <div>
      <h3>Authorization State</h3>
      {{if gt .TotalAssets 0}}
      <div class="bar-container">
        {{if gt .AuthorizedCount 0}}<div class="bar-segment bar-green" style="flex:{{.AuthorizedCount}}">{{.AuthorizedCount}}</div>{{end}}
        {{if gt .UnauthorizedCount 0}}<div class="bar-segment bar-red" style="flex:{{.UnauthorizedCount}}">{{.UnauthorizedCount}}</div>{{end}}
        {{if gt .AuthUnknownCount 0}}<div class="bar-segment bar-yellow" style="flex:{{.AuthUnknownCount}}">{{.AuthUnknownCount}}</div>{{end}}
      </div>
      {{end}}
      <table>
        <tr><td><span class="badge badge-green">Authorized</span></td><td>{{.AuthorizedCount}}</td></tr>
        <tr><td><span class="badge badge-red">Unauthorized</span></td><td>{{.UnauthorizedCount}}</td></tr>
        <tr><td><span class="badge badge-yellow">Unknown</span></td><td>{{.AuthUnknownCount}}</td></tr>
      </table>
    </div>
    <div>
      <h3>Managed State</h3>
      {{if gt .TotalAssets 0}}
      <div class="bar-container">
        {{if gt .ManagedCount 0}}<div class="bar-segment bar-green" style="flex:{{.ManagedCount}}">{{.ManagedCount}}</div>{{end}}
        {{if gt .UnmanagedCount 0}}<div class="bar-segment bar-red" style="flex:{{.UnmanagedCount}}">{{.UnmanagedCount}}</div>{{end}}
        {{if gt .MgmtUnknownCount 0}}<div class="bar-segment bar-yellow" style="flex:{{.MgmtUnknownCount}}">{{.MgmtUnknownCount}}</div>{{end}}
      </div>
      {{end}}
      <table>
        <tr><td><span class="badge badge-green">Managed</span></td><td>{{.ManagedCount}}</td></tr>
        <tr><td><span class="badge badge-red">Unmanaged</span></td><td>{{.UnmanagedCount}}</td></tr>
        <tr><td><span class="badge badge-yellow">Unknown</span></td><td>{{.MgmtUnknownCount}}</td></tr>
      </table>
    </div>
  </div>
</section>

{{if .EventSummary}}
<section>
  <h2>Event Summary</h2>
  <table>
    <thead>
      <tr><th>Event Type</th><th>Count</th></tr>
    </thead>
    <tbody>
    {{range $type, $count := .EventSummary}}
      <tr>
        <td>{{$type}}</td>
        <td>{{$count}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
</section>
{{end}}

<section>
  <h2>Asset Inventory</h2>
  <p>Total: {{.TotalAssets}} assets</p>
  <table>
    <thead>
      <tr>
        <th>Hostname</th>
        <th>Type</th>
        <th>OS</th>
        <th>Authorization</th>
        <th>Managed</th>
        <th>Source</th>
        <th>Owner</th>
        <th>Last Seen</th>
      </tr>
    </thead>
    <tbody>
    {{range .Assets}}
      <tr>
        <td>{{.Hostname}}</td>
        <td>{{.AssetType}}</td>
        <td>{{if .OSVersion}}{{.OSVersion}}{{else}}{{.OSFamily}}{{end}}</td>
        <td>
          {{if eq (printf "%s" .IsAuthorized) "authorized"}}<span class="badge badge-green">Authorized</span>
          {{else if eq (printf "%s" .IsAuthorized) "unauthorized"}}<span class="badge badge-red">Unauthorized</span>
          {{else}}<span class="badge badge-yellow">Unknown</span>
          {{end}}
        </td>
        <td>
          {{if eq (printf "%s" .IsManaged) "managed"}}<span class="badge badge-green">Managed</span>
          {{else if eq (printf "%s" .IsManaged) "unmanaged"}}<span class="badge badge-red">Unmanaged</span>
          {{else}}<span class="badge badge-yellow">Unknown</span>
          {{end}}
        </td>
        <td>{{.DiscoverySource}}</td>
        <td>{{.Owner}}</td>
        <td>{{.LastSeenAt.Format "2006-01-02T15:04:05Z"}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
</section>

<footer>
  Kite Collector {{.Version}} &mdash; Report generated {{.GeneratedAt}}
</footer>

</div>
</body>
</html>
`

// ---------------------------------------------------------------------------
// dashboard command
// ---------------------------------------------------------------------------

func newDashboardCmd() *cobra.Command {
	var (
		dbPath string
		addr   string
		noBrowser bool
	)

	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Open the browser-based dashboard",
		Long: `Start an embedded web server that provides a live view of assets,
software inventory, findings, and scan history. Data is read directly
from the local SQLite database — no external connections are made.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			st, err := sqlite.New(dbPath)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			defer func() { _ = st.Close() }()

			rc := dashboard.NewReportContext(ctx, st, dbPath, version, commit)

			logger := slog.Default()
			srv := dashboard.Serve(addr, st, rc, logger)

			go func() {
				logger.Info("dashboard listening", "addr", addr)
				if listenErr := srv.ListenAndServe(); listenErr != nil && listenErr != http.ErrServerClosed {
					logger.Error("dashboard server error", "error", listenErr)
				}
			}()

			if !noBrowser {
				dashboard.OpenBrowser("http://" + addr)
			}

			<-ctx.Done()
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutCancel()
			return srv.Shutdown(shutCtx)
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "./kite.db", "path to SQLite database")
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:9090", "listen address for the dashboard")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "do not open a browser automatically")

	return cmd
}

// ---------------------------------------------------------------------------
// double-click interactive menu (Windows Explorer / macOS Finder)
// ---------------------------------------------------------------------------

func runInteractiveMenu() {
	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║        kite-collector " + version + "          ║")
	fmt.Println("╠══════════════════════════════════════╣")
	fmt.Println("║  1) Run scan                         ║")
	fmt.Println("║  2) Open dashboard                   ║")
	fmt.Println("║  3) Show version                     ║")
	fmt.Println("║  4) Exit                             ║")
	fmt.Println("╚══════════════════════════════════════╝")
	fmt.Print("\nSelect [1-4]: ")

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return
	}

	switch strings.TrimSpace(scanner.Text()) {
	case "1":
		fmt.Println("\nStarting scan with defaults...")
		if err := runScan("kite-collector.yaml", nil, "table", "./kite.db", nil, false, false); err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		}
	case "2":
		fmt.Println("\nStarting dashboard...")
		os.Args = []string{os.Args[0], "dashboard"}
		if err := newRootCmd().Execute(); err != nil {
			fmt.Fprintf(os.Stderr, "Dashboard error: %v\n", err)
		}
	case "3":
		fmt.Printf("kite-collector %s (commit %s, built %s)\n", version, commit, date)
	case "4":
		fmt.Println("Bye!")
	default:
		fmt.Println("Invalid selection.")
	}

	fmt.Print("\nPress Enter to close...")
	scanner.Scan()
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	if osutil.IsDoubleClicked() {
		runInteractiveMenu()
		return
	}

	if err := newRootCmd().Execute(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
