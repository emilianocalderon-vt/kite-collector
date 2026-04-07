# kite-collector

Cybersecurity asset discovery, configuration audit, and posture analysis agent.

A single binary that scans your network, inventories installed software, audits system configuration for security weaknesses (CWE), and recommends mitigations based on attack patterns (CAPEC). Results are stored in a local SQLite database -- no servers, no dependencies, fully offline.

## Install

Download from [GitHub Releases](https://github.com/VulnerTrack/kite-collector/releases):

```bash
# Linux
curl -sSL https://github.com/VulnerTrack/kite-collector/releases/latest/download/kite-collector_linux_amd64.tar.gz | tar xz

# macOS
curl -sSL https://github.com/VulnerTrack/kite-collector/releases/latest/download/kite-collector_darwin_arm64.tar.gz | tar xz
```

Or build from source:

```bash
make build
```

## Usage

```bash
# Scan local host (works immediately, no config needed)
./kite-collector scan

# Scan a subnet
./kite-collector scan --scope 192.168.1.0/24

# Include Docker containers
./kite-collector scan --source docker

# JSON output
./kite-collector scan --output json

# Compare two scans to detect drift
./kite-collector diff scan1.db scan2.db

# Continuous monitoring
./kite-collector agent --stream --interval 6h
```

## What it discovers

| Source | Assets | Auth Required |
|--------|--------|--------------|
| Local agent | Hostname, OS, interfaces, installed packages | No |
| Network scan | Reachable hosts via TCP connect | No |
| Docker / Podman | Containers, images, networks | Socket access |
| UniFi | Clients (VLAN, switch port, signal), network devices | Controller credentials |
| AWS EC2 | EC2 instances across regions | IAM credentials |
| GCP Compute | Compute Engine VMs | ADC |
| Azure | Virtual machines across subscriptions | Service principal |
| Proxmox | VMs and LXC containers | API token |
| SNMP | Switches, routers, UPS devices | Community string |

## What it audits

The configuration audit checks your system and maps findings to [CWE](https://cwe.mitre.org/) weakness identifiers:

| Check | Example | CWE |
|-------|---------|-----|
| SSH root login permitted | `PermitRootLogin yes` | CWE-250 |
| Password authentication enabled | `PasswordAuthentication yes` | CWE-287 |
| No firewall active | iptables/nftables/ufw all inactive | CWE-284 |
| ASLR disabled | `randomize_va_space=0` | CWE-330 |
| Shadow file world-readable | `/etc/shadow` mode 644 | CWE-732 |
| Telnet service running | Port 23 listening | CWE-319 |
| Database exposed | Port 5432 on 0.0.0.0 | CWE-284 |

Findings are then matched against [CAPEC](https://capec.mitre.org/) attack patterns to generate actionable mitigations.

## Software inventory

Automatically detects and queries installed package managers:

| Package Manager | Platforms |
|----------------|-----------|
| dpkg | Debian, Ubuntu, Kali |
| pacman | Arch, Manjaro, EndeavourOS |
| rpm | RHEL, Fedora, CentOS, SUSE |

Each package gets a [CPE 2.3](https://nvd.nist.gov/products/cpe) identifier for vulnerability correlation with CVE databases.

## Configuration

Works out of the box with sane defaults and no config file. For customization, create a YAML config:

```yaml
discovery:
  sources:
    agent:
      enabled: true
      collect_software: true
    network:
      enabled: true
      scope: [192.168.1.0/24]
      tcp_ports: [22, 80, 443, 3389, 8080, 8443]
    docker:
      enabled: true
      host: unix:///var/run/docker.sock
    unifi:
      enabled: true
      endpoint: https://192.168.1.1:8443
      site: default

classification:
  authorization:
    allowlist_file: ./configs/authorized-assets.yaml
    match_fields: [hostname]

audit:
  enabled: true

stale_threshold: 168h   # 7 days
```

Environment variables override config with `KITE_` prefix (e.g. `KITE_LOG_LEVEL=debug`).

See `configs/kite-collector.example.yaml` for all options.

## Output formats

| Format | Use case |
|--------|---------|
| `--output table` | Terminal viewing (default) |
| `--output json` | SIEM ingestion, CI/CD pipelines, API consumption |
| `--output csv` | Spreadsheets, reporting |

## Commands

| Command | Description |
|---------|-------------|
| `scan` | One-shot discovery + audit + posture analysis |
| `agent --stream` | Continuous mode with configurable interval |
| `diff <db1> <db2>` | Compare two scan databases |
| `report` | Generate asset report |
| `version` | Print version, commit, build date |

## Asset classification

Every discovered asset is classified on two axes:

**Authorization** (is this asset supposed to be here?):
- `unknown` -- default, not yet evaluated
- `authorized` -- matches an entry in the allowlist
- `unauthorized` -- explicitly not in the allowlist

**Managed state** (does this asset meet our security controls?):
- `unknown` -- default, controls not configured
- `managed` -- all required controls present
- `unmanaged` -- missing one or more required controls

Assets never default to `authorized`. Only positive matches against your source of truth produce `authorized`.

## Database

All results are stored in a portable SQLite file at `./kite.db`:

```bash
# Query assets
sqlite3 kite.db "SELECT hostname, asset_type, is_authorized FROM assets"

# Query installed software
sqlite3 kite.db "SELECT software_name, version, cpe23 FROM installed_software LIMIT 10"

# Query config findings
sqlite3 kite.db "SELECT check_id, severity, cwe_id, title FROM config_findings"

# Query posture assessments
sqlite3 kite.db "SELECT capec_id, likelihood, mitigation FROM posture_assessments"

# Scan history
sqlite3 kite.db "SELECT started_at, status, total_assets FROM scan_runs ORDER BY started_at DESC"
```

## Platform integration

kite-collector can feed into the [Vulnertrack Intelligence Engine](https://github.com/VulnerTrack/vulnertrack-intelligence-engine) for cross-referencing assets against CVE/CWE/CAPEC databases:

```bash
# Import scan results into ClickHouse
vie kite scan --scope 192.168.1.0/24 --import

# Query imported assets
vie kite assets --authorized unauthorized
```

In streaming mode, OTLP events are pushed to an OpenTelemetry Collector for real-time monitoring.

## Security

- **Read-only** -- never writes to, modifies, or executes code on discovered systems
- **No credentials in storage** -- SQLite contains asset data only, never tokens or passwords
- **Structured logging** -- `log/slog` JSON output with automatic credential redaction
- **Minimal privileges** -- works as non-root with graceful degradation for permission-denied paths

## License

MIT -- see [LICENSE](LICENSE).
