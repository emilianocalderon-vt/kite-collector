# kite-collector

Cybersecurity asset discovery agent. A single Go binary that discovers network assets, enumerates installed software, classifies assets against an authorization allowlist, and stores results in local SQLite for offline analysis or streams events via OTLP for platform integration.

Part of the [Vulnertrack Intelligence Engine](../../README.md). Designed per [RFC-0031](../../docs/rfcs/kite-collector-go-based-cybersecurity-asset-management-agent.md).

## Overview

kite-collector solves the first step of cybersecurity asset management: **know what you have**. It runs as a zero-dependency CLI that scans your network, inventories the local host (OS, interfaces, installed packages), and classifies every asset as authorized or unauthorized against your source of truth.

What makes it different:

- **Offline-first** -- works with zero external dependencies in one-shot mode. The SQLite file is your checkpoint.
- **Compliance-aligned** -- maps directly to CIS Control 1 (asset inventory) and NIST SP 1800-5.
- **Never defaults to authorized** -- assets start as `unknown`. Only positive allowlist matches produce `authorized`.
- **Multi-platform software inventory** -- auto-detects and queries dpkg (Debian/Ubuntu), pacman (Arch), and rpm (RHEL/Fedora) with best-effort CPE 2.3 generation for vulnerability correlation.
- **Pure Go, no CGO** -- single static binary, cross-compiles to any OS/arch.

## Quick Start

```bash
# Build
make build

# Scan the local host (agent probe + software inventory, enabled by default)
./bin/kite-collector scan

# Scan a subnet
./bin/kite-collector scan --scope 192.168.1.0/24

# JSON output
./bin/kite-collector scan --scope 10.0.0.0/24 --output json

# Compare two scans
./bin/kite-collector diff scan1.db scan2.db

# Print version
./bin/kite-collector version
```

Or via the Python CLI wrapper:

```bash
vie kite build                                    # compile the Go binary
vie kite scan --scope 192.168.1.0/24 --import     # scan + import into ClickHouse
vie kite assets                                   # query discovered assets
vie kite status                                   # latest scan summary
```

## Architecture

```
ONE-SHOT MODE: kite-collector scan

  CLI --> ScanEngine.Run()
            |
            +--> Discovery Registry (parallel fan-out via errgroup)
            |      |-- NetworkScanner (TCP connect scan)
            |      +-- AgentProbe (local host: OS, interfaces)
            |
            +--> Deduplicator (stable UUID v7 identity)
            |
            +--> Classifier
            |      |-- is_authorized? (allowlist match)
            |      +-- is_managed? (control checklist)
            |
            +--> Software Collection (parallel per package manager)
            |      |-- dpkg-query (Debian/Ubuntu)
            |      |-- pacman -Q (Arch Linux)
            |      +-- rpm -qa (RHEL/Fedora/SUSE)
            |
            +--> SQLite Store (assets + software + events)
            |
            +--> Report (JSON / CSV / table)
```

### Software Collection Pipeline

The software collector uses a Strategy pattern with three-tier error isolation:

```
Tier 1: Line-level   -- bad parse line --> skip, record error, keep parsing
Tier 2: Collector     -- exec fails    --> log, keep other collectors' results
Tier 3: System        -- ctx cancelled --> return partial results collected so far
```

Each package manager collector auto-detects availability via `exec.LookPath`, runs in parallel, and generates best-effort CPE 2.3 identifiers (`cpe:2.3:a:*:curl:7.88.1:*:*:*:*:*:*:*`) for downstream vulnerability correlation with the platform's CVE/CWE database.

## Project Structure

```
apps/kite-collector/
  cmd/kite-collector/main.go      # cobra CLI entry point
  internal/
    config/                       # viper YAML + env var config
    model/                        # Asset, InstalledSoftware, Event, ScanRun structs
    discovery/                    # Pluggable source interface
      network/                    # TCP connect scanner
      agent/                      # Local host probe
        software/                 # Multi-platform package enumeration
          collector.go            # Collector interface, Result type, CollectError
          registry.go             # Auto-detect + parallel fan-out
          cpe.go                  # CPE 2.3 construction helper
          dpkg.go                 # Debian/Ubuntu (dpkg-query)
          pacman.go               # Arch Linux (pacman -Q)
          rpm.go                  # RHEL/Fedora (rpm -qa)
    classifier/                   # Authorization + managed classification
    dedup/                        # Identity resolution (SHA-256 natural key)
    store/                        # Store interface (repository pattern)
      sqlite/                     # SQLite implementation (modernc.org/sqlite)
    emitter/                      # Event push interface (noop for one-shot)
    engine/                       # Scan orchestration
    metrics/                      # Prometheus /metrics
    policy/                       # Severity rules, stale thresholds
  migrations/sqlite/              # SQL schema (assets, software, events, scan_runs)
  configs/                        # Example YAML config
  tests/                          # Integration and e2e tests
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `scan` | One-shot asset discovery scan |
| `agent` | Continuous streaming mode (Phase 2) |
| `diff` | Compare two SQLite scan files |
| `report` | Generate asset report |
| `version` | Print version, commit, build date |

### Scan Flags

```
--config string     Config file path (default: ./kite-collector.yaml)
--scope strings     CIDR ranges to scan (overrides config)
--output string     Output format: json, csv, table (default: table)
--db string         SQLite file path (default: ./data/kite.db)
--source strings    Enable specific sources (default: all configured)
-v, --verbose       Debug logging
```

## Configuration

kite-collector works out of the box with **sane defaults** and no config file:

| Setting | Default | Description |
|---------|---------|-------------|
| Agent probe | enabled | Collects hostname, OS, interfaces |
| Software collection | enabled | Enumerates installed packages |
| Interface collection | enabled | Lists network interfaces |
| Network scanner | disabled | Requires explicit `--scope` |
| Stale threshold | 168h (7 days) | Assets not seen in this window are flagged |
| Output format | table | Human-readable table |

For advanced configuration, copy `configs/kite-collector.example.yaml` and customize:

```yaml
discovery:
  sources:
    network:
      enabled: true
      scope: [192.168.1.0/24]
      tcp_ports: [22, 80, 443, 3389, 8080, 8443]
      timeout: 5s
      max_concurrent: 256
    agent:
      enabled: true
      collect_software: true      # enumerate installed packages
      collect_interfaces: true    # list network interfaces

classification:
  authorization:
    allowlist_file: ./configs/authorized-assets.yaml
    match_fields: [hostname, mac_address]

stale_threshold: 168h   # 7 days

metrics:
  enabled: true
  listen: :9090
```

Environment variables override config with `KITE_` prefix (e.g. `KITE_LOG_LEVEL=debug`).

## Software Inventory

kite-collector auto-detects available package managers and enumerates installed packages with zero configuration:

| Package Manager | Platforms | Command |
|----------------|-----------|---------|
| dpkg | Debian, Ubuntu, Kali | `dpkg-query -W -f='${Package}\t${Version}\n'` |
| pacman | Arch, Manjaro, EndeavourOS | `pacman -Q` |
| rpm | RHEL, Fedora, CentOS, SUSE | `rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n'` |

Each discovered package gets a best-effort [CPE 2.3](https://nvd.nist.gov/products/cpe) identifier, enabling correlation with CVE databases when results are imported into the Vulnertrack platform.

Software records are **fully replaced** on each scan (DELETE + INSERT in a single transaction), so uninstalled packages are automatically removed.

### Extending with new collectors

Implement the `software.Collector` interface and register in `software.NewRegistry()`:

```go
type Collector interface {
    Name() string
    Available() bool
    Collect(ctx context.Context) (*Result, error)
}
```

## Development

```bash
make all          # vet + lint + security + test + build
make test         # go test -race -count=1 ./...
make lint         # golangci-lint run ./...
make security     # gosec ./...
make vet          # go vet ./...
make build        # CGO_ENABLED=0 go build
make clean        # rm -rf bin/
```

### Prerequisites

- Go 1.26+
- [golangci-lint](https://golangci-lint.run/usage/install/)
- [gosec](https://github.com/securego/gosec) (for security scanning)

### Key Design Decisions

- **Pure Go, no CGO** -- `CGO_ENABLED=0` for deterministic cross-compilation. Uses `modernc.org/sqlite` instead of C sqlite3 bindings.
- **Interface-based DI** -- `Source`, `Store`, `Emitter`, and `software.Collector` interfaces enable testing and backend swapping with no global state.
- **Offline-first** -- One-shot mode works with zero external dependencies. SQLite file is the checkpoint.
- **Read-only discovery** -- Never writes to, modifies, or executes code on discovered systems.
- **Never defaults to authorized** -- Assets start as `unknown`. Only positive matches against a source-of-truth mark `authorized`.
- **Graceful degradation** -- Missing package managers are skipped. Parse errors on individual lines don't discard other results. A failing collector doesn't abort the scan.
- **Full replacement per scan** -- Software inventory is DELETE + INSERT per asset, not merged. This correctly handles uninstalled packages.

### Best Practices

**For operators:**
- Run scans on a schedule and use `diff` to detect drift between scan windows.
- Start with `collect_software: true` (default) to build a software baseline before importing into the platform for CVE correlation.
- Use the allowlist (`authorized-assets.yaml`) to separate known-good from shadow IT. Review `unauthorized` assets weekly per CIS Control 1.2.
- Export to JSON (`--output json`) for SIEM ingestion or CI/CD pipeline integration.

**For contributors:**
- Every new discovery source must implement `discovery.Source`. Every new package manager must implement `software.Collector`.
- Parse functions (e.g. `ParsePacmanOutput`) must be exported and unit-testable with raw strings -- keep them separate from `exec.CommandContext` calls.
- Tests use individual functions (not table-driven), `stretchr/testify`, and hand-written mock structs. Match existing patterns.
- New fields in the asset or software model require a documented purpose, a schema migration, and updated `scanAsset`/`scanSoftware` functions.

### Tech Stack

| Concern | Library |
|---------|---------|
| CLI | `spf13/cobra` + `spf13/viper` |
| SQLite | `modernc.org/sqlite` (pure Go) |
| UUID v7 | `google/uuid` |
| Metrics | `prometheus/client_golang` |
| Logging | `log/slog` (stdlib) |
| Testing | `stretchr/testify` |
| Concurrency | `golang.org/x/sync/errgroup` |

## Docker

```bash
docker build -t kite-collector .
docker run --rm kite-collector scan --scope 192.168.1.0/24
```

The image is built on `gcr.io/distroless/static-debian12:nonroot` (~15 MB).

## Platform Integration

In streaming mode (Phase 2), kite-collector pushes OTLP events to the Vulnertrack platform:

```
kite-collector --OTLP--> OTel Collector --> Python API --> ClickHouse
```

For one-shot mode, the Python CLI can import SQLite scan results directly:

```bash
vie kite scan --scope 192.168.1.0/24 --import
vie kite assets --authorized unauthorized
```

The software inventory with CPE identifiers enables the platform to JOIN discovered packages against the `mitre_attack` workspace's CVE/CWE/CAPEC data for per-asset vulnerability correlation.

## License

MIT -- see [LICENSE](LICENSE).
