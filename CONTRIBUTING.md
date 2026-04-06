# Contributing to kite-collector

## Prerequisites

- Go 1.26+
- [golangci-lint v2](https://golangci-lint.run/usage/install/) -- `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`
- [gosec](https://github.com/securego/gosec) -- `go install github.com/securego/gosec/v2/cmd/gosec@latest`
- [goreleaser](https://goreleaser.com/) (optional, for releases) -- `go install github.com/goreleaser/goreleaser/v2@latest`

## Build and test

```bash
make all          # vet + lint + security + test + build (run before every PR)
make build        # CGO_ENABLED=0 go build
make test         # go test -count=1 ./...
make test-e2e     # go test -tags e2e (requires Docker)
make lint         # golangci-lint run ./...
make security     # gosec ./...
make vet          # go vet ./...
make clean        # rm -rf bin/
```

`make all` must pass before submitting a PR. CI runs the same gates.

## Project structure

```
cmd/kite-collector/main.go      # CLI entry point (cobra commands)
internal/
  config/                       # viper YAML + env var config
  model/                        # Asset, InstalledSoftware, ConfigFinding, etc.
  discovery/                    # Pluggable discovery sources
    source.go                   # Source interface
    registry.go                 # Parallel fan-out orchestration
    agent/                      # Local host probe
      software/                 # Package manager collectors
    network/                    # TCP connect scanner
    docker/                     # Docker/Podman socket API
    unifi/                      # UniFi Controller REST API
    cloud/                      # AWS EC2, GCP Compute, Azure VMs
    proxmox/                    # Proxmox VE REST API
    snmp/                       # SNMP v2c/v3 walks
    cmdb/                       # ServiceNow, NetBox
    mdm/                        # Jamf, Intune, SCCM
  audit/                        # Configuration auditors
    auditor.go                  # Auditor interface
    ssh.go, firewall.go, ...    # Individual auditors
  posture/                      # CWE -> CAPEC matching engine
  classifier/                   # Authorization + managed classification
  dedup/                        # Identity resolution (SHA-256 natural key)
  store/                        # Store interface (repository pattern)
    sqlite/                     # SQLite implementation (modernc.org/sqlite)
    postgres/                   # PostgreSQL implementation (pgx/v5)
  emitter/                      # Event push (noop for one-shot, OTLP for streaming)
  engine/                       # Scan orchestration
  metrics/                      # Prometheus /metrics
  policy/                       # Severity rules, stale thresholds
api/
  rest/                         # REST API (net/http ServeMux)
  grpc/                         # gRPC streaming endpoint
migrations/sqlite/              # Embedded SQL schema
configs/                        # Example YAML config
tests/                          # Integration and e2e tests
```

## Constraints

These are non-negotiable:

- **CGO_ENABLED=0** -- pure Go only. No C dependencies. This ensures cross-compilation works and the binary is a single static file.
- **Read-only discovery** -- never write to, modify, or execute code on discovered systems. This is a binding rule.
- **No vendor SDKs** -- all API connectors use raw `net/http` + JSON. Keeps the binary small and avoids SDK version churn.
- **Never default to authorized** -- assets must start as `unknown`. Only positive allowlist matches produce `authorized`.
- **Credentials via environment variables** -- never in config files, never in logs, never in SQLite.

## Adding a discovery source

1. Create `internal/discovery/yourname/yourname.go`
2. Implement the `Source` interface:

```go
type Source interface {
    Name() string
    Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
}
```

3. Register in `cmd/kite-collector/main.go`:

```go
registry.Register(yourname.New())
```

4. Add config fields to `internal/config/config.go` if needed
5. Credentials via `KITE_YOURNAME_*` environment variables
6. Handle errors gracefully -- log and return partial results, never crash the scan
7. Add unit tests with `httptest` mock servers

## Adding a package manager collector

1. Create `internal/discovery/agent/software/yourpkg.go`
2. Implement the `Collector` interface:

```go
type Collector interface {
    Name() string
    Available() bool
    Collect(ctx context.Context) (*Result, error)
}
```

3. Register in `software.NewRegistry()`
4. Use `exec.LookPath` in `Available()` to auto-detect
5. Parse functions must be exported and testable with raw strings (e.g. `ParseYourPkgOutput(output string)`)
6. Generate CPE 2.3 identifiers via `BuildCPE23(vendor, product, version)`

## Adding a configuration auditor

1. Create `internal/audit/youraudit.go`
2. Implement the `Auditor` interface:

```go
type Auditor interface {
    Name() string
    Audit(ctx context.Context, asset model.Asset) ([]model.ConfigFinding, error)
}
```

3. Each finding must include a CWE ID, severity, evidence (what was observed), and remediation (how to fix)
4. Handle permission denied gracefully -- log and skip, don't crash
5. Register in the audit registry in `engine.go`

## Code style

- **Logging**: `log/slog` (stdlib). DEBUG for routine, INFO for state changes, WARN for recoverable errors, ERROR for failures.
- **Formatting**: `gofumpt` via golangci-lint. Run `make lint` to check.
- **Errors**: wrap with `fmt.Errorf("context: %w", err)`. Never suppress errors with `_` unless documented.
- **Testing**: `stretchr/testify` for assertions. Individual test functions, not table-driven. Hand-written mocks, no mock generators.
- **Naming**: follow Go conventions. Interfaces in their own file (e.g. `source.go`, `auditor.go`, `store.go`).

## Commit conventions

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(discovery): add Proxmox VM enumeration
fix(audit): handle missing sshd_config gracefully
test(store): add PostgreSQL integration tests
docs: update README with SNMP configuration
chore(ci): fix golangci-lint version in CI
```

## CI/CD

GitHub Actions runs on every push to main:

```
vet -> lint -> security -> test -> build (linux/darwin/windows x amd64/arm64)
```

Releases are triggered by pushing a version tag:

```bash
git tag -a v0.2.0 -m "v0.2.0: description"
git push origin v0.2.0
```

GoReleaser produces multi-platform binaries with SHA256 checksums and a GitHub Release.

## Tech stack

| Concern | Library | Why |
|---------|---------|-----|
| CLI | `spf13/cobra` + `spf13/viper` | De facto Go CLI standard |
| SQLite | `modernc.org/sqlite` | Pure Go, no CGO |
| PostgreSQL | `jackc/pgx/v5` | Best Go PG driver |
| UUID v7 | `google/uuid` | Time-ordered, matches Python-side `uuid.uuid7()` |
| Metrics | `prometheus/client_golang` | Standard Prometheus client |
| Logging | `log/slog` (stdlib) | No extra dependency |
| Testing | `stretchr/testify` | Assertions and mocks |
| Concurrency | `golang.org/x/sync/errgroup` | Parallel fan-out with error propagation |
| OTLP | HTTP+JSON | No gRPC/protobuf dependency |
| REST API | `net/http` ServeMux | Stdlib, no external router |
| Release | `goreleaser` | Multi-platform binaries + checksums |

## Guidelines

See [guidelines.md](guidelines.md) for the full project philosophy, binding rules, and architectural decisions.
