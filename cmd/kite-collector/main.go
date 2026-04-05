package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnertrack/kite-collector/api/rest"
	"github.com/vulnertrack/kite-collector/internal/classifier"
	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/dedup"
	"github.com/vulnertrack/kite-collector/internal/discovery"
	"github.com/vulnertrack/kite-collector/internal/discovery/agent"
	"github.com/vulnertrack/kite-collector/internal/discovery/cloud"
	"github.com/vulnertrack/kite-collector/internal/discovery/network"
	"github.com/vulnertrack/kite-collector/internal/emitter"
	"github.com/vulnertrack/kite-collector/internal/engine"
	"github.com/vulnertrack/kite-collector/internal/metrics"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/policy"
	"github.com/vulnertrack/kite-collector/internal/store"
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
		newVersionCmd(),
	)

	return root
}

// ---------------------------------------------------------------------------
// scan command
// ---------------------------------------------------------------------------

func newScanCmd() *cobra.Command {
	var (
		cfgFile string
		scope   []string
		output  string
		dbPath  string
		sources []string
		verbose bool
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run an asset discovery scan",
		Long: `Execute a full scan cycle: discover assets from enabled sources, deduplicate
against the local database, classify authorization and managed state, evaluate
policy rules, persist results, and emit lifecycle events.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cfgFile, scope, output, dbPath, sources, verbose)
		},
	}

	cmd.Flags().StringVar(&cfgFile, "config", "kite-collector.yaml", "path to configuration file")
	cmd.Flags().StringSliceVar(&scope, "scope", nil, "CIDR scopes (overrides config)")
	cmd.Flags().StringVar(&output, "output", "table", "output format: json, csv, table")
	cmd.Flags().StringVar(&dbPath, "db", "./data/kite.db", "path to SQLite database")
	cmd.Flags().StringSliceVar(&sources, "source", nil, "discovery sources to enable")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable debug logging")

	return cmd
}

func runScan(cfgFile string, scope []string, output, dbPath string, sources []string, verbose bool) error {
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

	// Set up deduplicator.
	dd := dedup.New(st)

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

	// Set up metrics.
	met := metrics.New()
	if cfg.Metrics.Enabled {
		listen := cfg.Metrics.Listen
		if listen == "" {
			listen = ":9090"
		}
		met.Serve(listen)
	}

	// Create and run the scan engine.
	eng := engine.New(st, registry, dd, cls, em, pol, met)

	result, err := eng.Run(ctx, cfg)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Print scan summary to stderr.
	_, _ = fmt.Fprintf(os.Stderr, "\nScan complete: %d total, %d new, %d updated, %d stale, %d events\n",
		result.TotalAssets, result.NewAssets, result.UpdatedAssets,
		result.StaleAssets, result.EventsEmitted)

	// Output asset list.
	assets, err := st.ListAssets(ctx, store.AssetFilter{})
	if err != nil {
		return fmt.Errorf("list assets: %w", err)
	}

	switch strings.ToLower(output) {
	case "json":
		return formatJSON(assets)
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
	cmd.Flags().StringVar(&dbPath, "db", "./data/kite.db", "path to SQLite database")
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

	logLevel := slog.LevelInfo
	if verbose || strings.EqualFold(cfg.LogLevel, "debug") {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	dataDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir %s: %w", dataDir, err)
	}

	st, err := sqlite.New(dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = st.Close() }()

	if err = st.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate store: %w", err)
	}

	registry := discovery.NewRegistry()
	registry.Register(network.New())
	registry.Register(agent.New())
	registry.Register(cloud.NewAWS())
	registry.Register(cloud.NewGCP())
	registry.Register(cloud.NewAzure())

	dd := dedup.New(st)

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

	met := metrics.New()
	if cfg.Metrics.Enabled {
		listen := cfg.Metrics.Listen
		if listen == "" {
			listen = ":9090"
		}
		met.Serve(listen)
	}

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
Supported formats: json, csv, table.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReport(dbPath, format, output)
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "./data/kite.db", "path to SQLite database")
	cmd.Flags().StringVar(&format, "format", "table", "report format: json, csv, table")
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
		return formatJSON(report)
	case "csv":
		formatCSV(assets)
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
		},
	}
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
// main
// ---------------------------------------------------------------------------

func main() {
	if err := newRootCmd().Execute(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
