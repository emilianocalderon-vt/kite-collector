# VulnerTrack Guidelines
This document defines the foundational guidelines that govern how VulnerTrack is designed, built, extended, and maintained. It is the authoritative reference for contributors, integrators, and adopters on what principles the project upholds and why. Guidelines are binding for all code, documentation, and integrations that form part of the VulnerTrack project.

***
## 1. Core Philosophy
### 1.1 Standards-First
VulnerTrack never invents a protocol, schema, or data format when an established, widely-adopted standard already exists. Every technical decision — telemetry transport, metrics exposition, asset classification vocabulary, event structure — must first be evaluated against existing standards before defining something new. The rationale is simple: security and IT teams already operate in ecosystems shaped by OpenTelemetry, Prometheus, NIST, CIS, and ISO; tools that speak those languages are adopted; tools that invent competing standards become silos.[^1][^2][^3][^4][^5]

**Binding rule:** A new format, field name, or protocol may only be introduced if no existing standard covers the use case, and the decision must be documented with an explicit rationale explaining why existing standards are insufficient.
### 1.2 Trust Is Earned Locally First
VulnerTrack must work completely offline and with zero external dependencies in one-shot CLI mode. Users evaluating the tool must be able to run a full scan, inspect all collected data in a local SQLite file using standard tools, and verify behavior before enabling any network-outbound features. Streaming and centralized collection are opt-in, not default.[^6][^7][^8][^9]

**Binding rule:** The `vulnertrack scan` command must never require network access beyond the configured discovery scope. No telemetry, analytics, or update checks may run without explicit user consent.
### 1.3 Data Minimization and Transparency
VulnerTrack only collects the minimum data required to support its declared use cases. Every field in the asset model must have a documented purpose and a clear mapping to at least one supported use case (CSAM, compliance, lifecycle, exposure). Fields without documented purpose must not be collected or stored.[^9][^10]

**Binding rule:** The full list of fields collected per asset type must be documented in `docs/architecture.md` and kept current. Users must be able to inspect everything VulnerTrack collects by querying the local SQLite file or the API.
### 1.4 Security by Default
As a security-focused tool, VulnerTrack must hold itself to security standards that match or exceed its use case. Default configurations must be secure. Credentials, tokens, and secrets must never appear in logs, SQLite files, or emitted events. TLS must be enabled by default for all network communication.[^11][^12]

**Binding rule:** Any configuration that weakens security (e.g., disabling TLS, skipping certificate validation) must require an explicit flag and emit a visible warning.

***
## 2. Telemetry and Data Guidelines
### 2.1 Push Model for Events (OTel)
VulnerTrack uses a **push model** for asset and exposure events, aligned with the OpenTelemetry push architecture. The agent/CLI generates events when state changes are detected and pushes them to the configured endpoint. The platform (API or OTel Collector) never polls individual agents.[^1][^13][^14]

Rationale: asset discovery events are irregular, security-relevant facts, not periodic metrics. Push better supports real-time detection of unauthorized assets. Additionally, agents frequently run behind NAT, firewalls, or in cloud environments where inbound connections are restricted, making pull impractical.[^15][^16]
### 2.2 Pull Model Only for Aggregate KPIs (Prometheus)
The Prometheus `/metrics` endpoint on the VulnerTrack API is a **secondary, optional surface** for aggregate KPIs only. It does not expose individual asset records or raw events. Its sole purpose is to allow teams to integrate VulnerTrack health and CSAM KPIs into existing Grafana/Prometheus dashboards without additional integration work.[^17][^18][^19]

**Binding rule:** Raw asset records and events must never be exposed via the Prometheus endpoint. Only counters, gauges, and summaries aggregated at the inventory level are permitted.
### 2.3 OTLP as the Event Transport Standard
All streaming events emitted by VulnerTrack agents must be structured as OTLP-compatible log records or metrics. Every event must include standard OTel resource attributes (`service.name`, `service.version`, `host.name`) and instrumentation scope. This ensures VulnerTrack events can be routed through any OTel Collector pipeline alongside application logs, traces, and metrics.[^1][^20][^21]

**Binding rule:** Event schemas must be validated against OTel semantic conventions before being stabilized. Any deviation from OTel conventions must be documented.
### 2.4 Event Schema Stability
Once an event type is published in a stable release, its required fields must not be removed or renamed in minor or patch versions. Additive changes (new optional fields) are allowed in minor versions. Breaking changes require a major version bump, a deprecation notice in the prior minor version, and a migration guide.[^11][^12]

***
## 3. Asset Classification Guidelines
### 3.1 Authorized vs Unauthorized
The `is_authorized` field is the most security-critical field in the asset model. It must be derived by matching discovered assets against at least one configured "source of truth" (CMDB, Active Directory, MDM, cloud account inventory, or an explicit allowlist). A missing or empty source-of-truth configuration must result in `is_authorized: unknown`, never `is_authorized: true`.[^9][^22]

**Binding rule:** VulnerTrack must never default to marking assets as authorized. The default posture is `unknown`; `true` requires a positive match.[^23][^9]
### 3.2 Managed vs Unmanaged
The `is_managed` field reflects whether an asset has the required security controls installed and reporting. Required controls are configurable per environment (e.g., EDR agent, MDM enrollment, disk encryption). An asset is `is_managed: false` if any required control is missing or not recently reporting.[^9][^24][^10]

**Binding rule:** The list of required controls that determine `is_managed` must be explicitly configurable and must default to an empty set (opt-in). Organizations define their own control requirements.
### 3.3 Severity Assignment
`UnauthorizedAssetDetected` and `UnmanagedAssetDetected` events carry a `severity` field. Severity must be derived from configurable rules (e.g., unauthorized asset in a `prod` environment → high; in `dev` → low). Default severity rules must be documented and must err on the side of higher severity in the absence of environment context.[^9][^25][^10]

***
## 4. Discovery Guidelines
### 4.1 Minimum Discovery Scope for v1
VulnerTrack v1 must support at minimum:

- **Network-based discovery:** Active scanning of configured IP ranges for live hosts (ICMP, TCP SYN, ARP).[^8][^9]
- **Agent-based discovery:** A lightweight agent that runs on an endpoint and pushes asset metadata on a schedule.
- **Cloud API discovery:** Read-only API queries to cloud providers (AWS, GCP, Azure) to enumerate VMs, managed services, containers, and accounts.[^26][^9]

Additional sources (MDM APIs, AD/LDAP, Kubernetes, SaaS APIs) are supported as pluggable connectors.
### 4.2 Discovery Must Be Read-Only
Discovery operations must never modify, configure, or affect discovered systems. Active scanning must be limited to identification; no exploitation, credential testing, or service manipulation is permitted under any configuration.[^8][^9]

**Binding rule:** A code review checklist item must verify that no discovery module writes to, modifies, or executes code on a target system.
### 4.3 Discovery Frequency and Impact
Default scan intervals must be set to minimize network impact. Aggressive scanning that could trigger IDS/IPS alerts or degrade network performance must require explicit opt-in configuration and carry a visible warning in the CLI output and documentation.[^8][^9]
### 4.4 Least Privilege for Cloud Connectors
Cloud provider connectors must document the minimum IAM permissions required and must use read-only policies. Example IAM policy documents must be maintained in `docs/connectors/`.[^9][^27]

***
## 5. Data Quality Guidelines
### 5.1 Asset Identity and Deduplication
Every discovered asset must be assigned a stable `asset_id` (UUID) that persists across scan runs. Deduplication logic must use a configurable set of identifiers (hostname, MAC, cloud instance ID) to match new observations to existing records. Deduplication rules must be documented and testable.[^8][^9]
### 5.2 `last_seen` Freshness
Every asset record must carry a `last_seen` timestamp that reflects the most recent confirmed observation. Assets that exceed a configurable `stale_threshold` must be flagged and optionally emit an `AssetNotSeen` event. Stale data must be clearly indicated in reports and API responses.[^8][^28]
### 5.3 Coverage Reporting
VulnerTrack must report discovery coverage explicitly: what percentage of the configured scope was successfully scanned, how many errors occurred, and which sources of truth were reachable. Coverage data must appear in every scan report and in the Prometheus metrics surface.[^8][^9]

***
## 6. Compliance and Framework Alignment Guidelines
VulnerTrack's output must be directly usable as evidence for the following frameworks. Contributors must ensure that new features do not break alignment with these controls.[^8][^9][^22][^27]

| Framework | Minimum alignment requirement |
|---|---|
| NIST SP 1800-5[^8][^29] | Asset model must cover all NIST-recommended attributes; lifecycle states must be supported |
| CIS Control 1.1[^22][^23] | Scan output must be exportable as a detailed asset inventory with all required fields |
| CIS Control 1.2[^22][^23] | `UnauthorizedAssetDetected` events must be generated within one scan cycle of detection; remediation workflows must be documentable |
| ISO 27001 A.8[^27][^30] | `owner`, `asset_type`, `lifecycle_state`, and classification fields must be present and queryable |
| NIST CSF 2.0 ID.AM[^8][^9] | Continuous discovery and classification must feed the Identify function; API must support export to CMDB or SIEM |

A compliance alignment table must be maintained in `docs/compliance.md` and updated with every release.

***
## 7. Open Source Governance Guidelines
### 7.1 Licensing
VulnerTrack is licensed under [chosen OSS license, e.g., Apache 2.0]. All contributions must be compatible with this license. Third-party dependencies must be reviewed for license compatibility before inclusion.[^11]
### 7.2 Contribution Process
All contributions must go through a pull request with at least one maintainer review. Contributions must include:

- Unit tests for new logic
- Documentation updates for new fields, commands, or behaviors
- An update to `CHANGELOG.md`

No direct commits to `main` or `release/*` branches are permitted, including from maintainers.[^11][^12]
### 7.3 Security Disclosure Policy
VulnerTrack follows a coordinated vulnerability disclosure policy documented in `SECURITY.md`. Security issues must not be reported as public GitHub issues. Reporters must use the designated private channel. Maintainers commit to acknowledging reports within 72 hours and publishing a fix or mitigation within 90 days for critical issues.[^11][^12]
### 7.4 API and Schema Versioning
VulnerTrack follows semantic versioning (SemVer). Breaking changes to:

- The SQLite schema
- Event schemas and event type names
- CLI command names, flags, and output formats
- REST API request/response shapes

...require a major version bump. A minimum one minor version deprecation notice must precede any breaking change. Deprecation warnings must appear in CLI output and API responses.[^11][^12]
### 7.5 Roadmap and Decision Transparency
Significant architectural decisions must be recorded as Architecture Decision Records (ADRs) in `docs/decisions/`. Each ADR documents the context, the decision, the alternatives considered, and the rationale. This ensures that future contributors can understand why the project is shaped the way it is, rather than reversing decisions unknowingly.[^11][^12]
### 7.6 Dependency Management
All dependencies must be pinned to specific versions in the Go module file. Dependency updates must go through the standard PR process and must not be merged without passing the full test suite. Automated dependency scanning must run on every PR.[^11]

***
## 8. Integration Guidelines
### 8.1 Integration Must Be Additive
VulnerTrack integrations (connectors, exporters, webhooks) must not modify the core asset model or event schema. They consume data from VulnerTrack and produce output for external systems, but the canonical asset record always lives in VulnerTrack.[^1][^13][^20]
### 8.2 Supported Integration Surfaces (v1)
- **SQLite file** — direct SQL queries for scripting and automation
- **REST API** — asset queries, event queries, inventory exports
- **OTLP export** — push events to any OTel Collector
- **Prometheus `/metrics`** — scrape aggregate KPIs
- **JSON/CSV export** — from CLI for CI/CD, SIEM ingestion, spreadsheets
### 8.3 Integration Documentation
Every supported integration must have a dedicated page in `docs/integrations/` that documents required configuration, minimum permissions, example commands or configuration snippets, and known limitations.[^11]

***
## 9. Technology Stack
### 9.1 Core Stack
VulnerTrack is built on a deliberately minimal, production-proven stack. Every component was chosen because it is widely understood in the Go/cloud-native ecosystem, has strong OSS community backing, and avoids unnecessary abstraction layers that would complicate contributions.[^1][^3][^11]

| Layer | Technology | Rationale |
|---|---|---|
| Language | Go | Single binary compilation, strong concurrency model (goroutines), excellent cloud/network libraries, native CLI tooling ecosystem[^31][^32] |
| One-shot storage | SQLite (via `modernc.org/sqlite` — pure Go, no CGO) | Zero-dependency, file-portable, queryable with standard SQL tools, diffable between runs |
| Streaming transport | OTLP over HTTP/gRPC (OpenTelemetry Protocol) | Vendor-neutral, widely supported by OTel Collectors and backends[^1][^13][^20] |
| Backend storage | PostgreSQL | Reliable, mature, JSONB support for flexible asset attributes, strong Go driver ecosystem (`pgx`) |
| Backend API | REST + gRPC (dual surface) | REST for human-facing clients and integrations; gRPC for high-throughput agent→API streaming |
| CLI framework | `cobra` + `viper` | De facto standard for Go CLIs; supports subcommands, flags, config files, and environment variables |
| Metrics surface | Prometheus exposition format (`prometheus/client_golang`) | Drop-in compatibility with any Prometheus scraper and Grafana[^17][^18][^19] |
| Structured logging | `log/slog` (Go stdlib, ≥1.21) | Standard library, structured JSON output, no extra dependency |
| Configuration | YAML file + environment variables (via `viper`) | Human-readable, widely understood in DevOps/infra tooling |
| Testing | `testing` (stdlib) + `testify` + `testcontainers-go` | Unit, integration, and container-based end-to-end tests in a single framework |
| Build and release | `goreleaser` | Multi-platform binary builds, checksums, container images, and release notes automation |
| Container | Distroless or Alpine base image | Minimal attack surface for the agent container image |
### 9.2 Component Map
The VulnerTrack codebase is organized into the following top-level components. Each component has a single responsibility and communicates with others through defined interfaces, never through shared global state.

```
vulnertrack/
├── cmd/                    # CLI entry points (cobra commands)
│   ├── scan/               # One-shot scan command
│   ├── agent/              # Continuous streaming agent
│   ├── diff/               # Compare two SQLite scan results
│   └── report/             # Generate exports (JSON, CSV, HTML)
│
├── internal/
│   ├── discovery/          # Discovery engine (pluggable sources)
│   │   ├── network/        # Network scanner (ICMP, TCP, ARP)
│   │   ├── cloud/          # Cloud API connectors (AWS, GCP, Azure)
│   │   ├── agent/          # Local agent probe (OS, software, controls)
│   │   └── mdm/            # MDM/CMDB API connectors
│   │
│   ├── model/              # Asset, Event, and Policy data models (Go structs)
│   ├── classifier/         # Authorization and management classification logic
│   ├── dedup/              # Asset deduplication and identity resolution
│   ├── store/
│   │   ├── sqlite/         # SQLite read/write for one-shot mode
│   │   └── postgres/       # PostgreSQL persistence for streaming mode
│   │
│   ├── emitter/            # Event emitter: OTLP HTTP/gRPC push
│   ├── metrics/            # Prometheus metrics registry and collectors
│   └── policy/             # Policy engine: severity rules, control requirements
│
├── api/                    # Backend API server
│   ├── rest/               # REST handlers (asset queries, exports, events)
│   ├── grpc/               # gRPC server (agent streaming endpoint)
│   └── metrics/            # /metrics Prometheus endpoint
│
├── docs/                   # Documentation (architecture, guidelines, compliance)
├── configs/                # Example configuration files
└── tests/                  # Integration and e2e tests
```
### 9.3 Data Flow: One-Shot Mode
```
[vulnertrack scan]
      │
      ▼
[Discovery Engine]
  ├── NetworkScanner.Scan(scope)
  ├── CloudConnector.List(provider, account)
  └── AgentProbe.Collect(localhost)
      │
      ▼
[Deduplicator]  ←──── existing SQLite records (if any)
      │
      ▼
[Classifier]
  ├── is_authorized? → match against source-of-truth (CMDB / allowlist)
  └── is_managed?   → check required controls present
      │
      ▼
[SQLite Store]
  ├── assets table
  ├── events table
  └── scan_runs table
      │
      ▼
[Report Generator]
  └── JSON / CSV / HTML output
```
### 9.4 Data Flow: Continuous Streaming Mode
```
[vulnertrack agent --stream]
      │
      ▼
[Discovery Engine]  (runs on schedule, configurable interval)
      │
      ▼
[Deduplicator]  ←──── in-memory state + last known state from API
      │
      ▼
[Classifier]
      │
      ▼
[Event Emitter]
  ├── AssetDiscovered
  ├── AssetUpdated
  ├── UnauthorizedAssetDetected
  ├── UnmanagedAssetDetected
  └── AssetNotSeen
      │
      ▼
[OTLP HTTP/gRPC push]
      │
      ├──▶ [VulnerTrack API]     (primary backend)
      └──▶ [OTel Collector]      (optional, if configured)

[VulnerTrack API]
  ├── gRPC ingest endpoint
  ├── PostgreSQL (asset graph + event log)
  ├── REST query API
  └── /metrics  (Prometheus scrape endpoint)
```

***
## 10. Feature Development Workflow
All new features in VulnerTrack follow a structured workflow from proposal to release. This ensures that changes are intentional, traceable, standards-aligned, and do not silently break existing integrations or compliance mappings.[^11][^12]
### 10.1 Step 1 — Feature Proposal (RFC or Issue)
Every non-trivial feature starts as a GitHub Issue or RFC (Request for Comments) document in `docs/decisions/`. The proposal must answer:

- **What problem does this solve?** Link to a specific use case, compliance control, or user pain point.
- **Which standard or framework does this align with?** If none, explain why the feature is still in scope.
- **What data does it collect or expose?** List new fields, events, or API endpoints.
- **Does it introduce a breaking change?** If yes, describe the migration path.
- **What are the alternatives?** Document at least one alternative and why it was not chosen.

Maintainers triage proposals weekly. A proposal is accepted, deferred, or rejected with a written rationale.[^11][^12]
### 10.2 Step 2 — Architecture Decision Record (ADR)
For features that affect the asset model, event schema, API surface, telemetry transport, or discovery engine, an Architecture Decision Record must be created in `docs/decisions/NNNN-title.md` before implementation begins. The ADR format follows the Michael Nygard template: **Context → Decision → Consequences**. ADRs are immutable once merged; superseded ADRs are marked as such and reference their replacement.[^11]
### 10.3 Step 3 — Design Review
For features involving new asset fields, event types, or API endpoints, a design review is required before a PR is opened. The design review is conducted as a GitHub Discussion or synchronous call and must confirm:

- The data model change is backward-compatible or a major version bump is planned.
- The new event type follows OTel semantic conventions and VulnerTrack event schema guidelines.[^1][^14]
- Compliance alignment table in `docs/compliance.md` does not need to be invalidated.
- Security implications have been assessed (data minimization, credential handling, least-privilege discovery).[^11][^12]
### 10.4 Step 4 — Implementation
Implementation follows these rules:

- **One concern per PR.** A PR must not mix feature implementation with refactoring or documentation unless they are inseparable.
- **Test-first for classifiers and emitters.** The `classifier/` and `emitter/` packages require unit tests before merging. `testify` assertions and `testcontainers-go` for integration tests involving SQLite or PostgreSQL.[^31][^11]
- **No new global state.** All dependencies (store, emitter, classifier) must be injected via interfaces. This keeps components testable and swappable.
- **Structured logging for all new paths.** Every new discovery source, classification decision, and event emission must produce a `slog` log entry at the appropriate level (DEBUG for routine, INFO for state changes, WARN for recoverable errors, ERROR for failures).
- **Config-first for behavior.** New behavior that varies per deployment (thresholds, intervals, severity rules, required controls) must be configurable via the YAML config file and overridable by environment variable.
### 10.5 Step 5 — Pull Request Review Checklist
Every PR must pass the following checklist before merge:

```
[ ] Unit tests added or updated
[ ] Integration tests added for new store or API paths
[ ] CHANGELOG.md updated under [Unreleased]
[ ] docs/architecture.md updated if component map changed
[ ] docs/guidelines.md updated if a new guideline was added
[ ] docs/compliance.md updated if compliance alignment changed
[ ] No credentials, tokens, or PII in logs or test fixtures
[ ] No new CGO dependencies (pure Go only)
[ ] New fields in asset model have documented purpose
[ ] New event types follow OTel attribute naming conventions
[ ] Breaking changes documented with migration guide
[ ] goreleaser config updated if new binary or artifact added
```
### 10.6 Step 6 — Release
VulnerTrack uses `goreleaser` for automated releases. Releases are triggered by a version tag (`vX.Y.Z`) on `main`. Every release produces:

- Multi-platform binaries (Linux amd64/arm64, macOS amd64/arm64, Windows amd64)
- Container images tagged with version and `latest`
- SHA256 checksums for all artifacts
- A GitHub Release with auto-generated changelog from PR titles and labels
- An updated `docs/compliance.md` snapshot for the release version

Release candidates (`vX.Y.Z-rc.N`) are published for major releases and must be validated against the integration test suite in a real environment before promotion to stable.[^11][^12]

***



The following patterns are explicitly prohibited in VulnerTrack's design and implementation:

| Anti-pattern | Why it is prohibited |
|---|---|
| Defaulting assets to `is_authorized: true` | Creates false sense of security; violates CIS 1.2[^22][^23] |
| Collecting fields without documented purpose | Violates data minimization principle; reduces user trust[^9][^11] |
| Inventing new transport protocols | Fragments the ecosystem; increases adoption friction[^1][^3] |
| Requiring a server for one-shot scan mode | Prevents offline and CI/CD usage; breaks trust model[^6][^7] |
| Hardcoding severity without configuration | Different environments have different risk tolerances[^9][^25] |
| Breaking changes in minor/patch versions | Breaks downstream integrations without warning[^11][^12] |
| Writing to or modifying discovered systems | Transforms a visibility tool into a risk; violates read-only principle[^8][^9] |
| Logging credentials or tokens | Fundamental security failure for a security tool[^11] |

---

## References

1. [Prometheus and OpenTelemetry - Better Together](https://opentelemetry.io/blog/2024/prom-and-otel/) - OpenTelemetry (OTel for short), is a vendor-neutral open standard for instrumenting, generating, col...

2. [Open standards in 2026: The backbone of modern observability](https://grafana.com/blog/observability-survey-OSS-open-standards-2026/) - The two de facto open standards in observability today are Prometheus and OpenTelemetry. Yes, they'r...

3. [OpenTelemetry](https://opentelemetry.io) - OpenTelemetry is an open source observability framework for cloud native software. ... Export teleme...

4. [Why we built our observability platform on open standards](https://chronosphere.io/learn/why-we-built-on-open-standards/) - Open standards like Prometheus and OpenTelemetry were emerging as the common language. They could ei...

5. [From chaos to clarity: How OpenTelemetry unified observability ...](https://www.cncf.io/blog/2025/11/27/from-chaos-to-clarity-how-opentelemetry-unified-observability-across-clouds/) - OpenTelemetry is an open-source standard for collecting traces, metrics, and logs. As part of the CN...

6. [Open Source Asset Management Software: Pros and Cons - Infraon](https://infraon.io/blog/open-source-asset-management-software-pros-cons/) - Open source asset management software gives organizations full control over asset tracking, cost str...

7. [Optimising IT with Open Source: A Guide to Asset Management ...](https://www.opensourceforu.com/2025/07/optimising-it-with-open-source-a-guide-to-asset-management-solutions/) - By leveraging open source tools, businesses can gain granular visibility into their IT environment, ...

8. [IT Asset Management - NCCoE - NIST](https://www.nccoe.nist.gov/publication/1800-5/VolB/) - This guide aids those responsible for tracking assets, configuration management, and cybersecurity i...

9. [Using information technology asset management (ITAM) to enhance ...](https://www.cyber.gc.ca/en/guidance/using-information-technology-asset-management-itam-enhance-cyber-security-itsm10004) - Keeping track of all your assets is critical to cyber security and to the operational and financial ...

10. [Cybersecurity Asset Management (CSAM): Definition, Benefits ...](https://www.tanium.com/blog/what-is-cybersecurity-asset-management-csam/) - Unsecured cyber assets can become entry points for cyber threats, leading to data breaches, unauthor...

11. [Best Practices For Open-Source Governance - Meegle](https://www.meegle.com/en_us/topics/open-source-governance/best-practices-for-open-source-governance) - Governance ensures that open-source projects remain transparent, collaborative, and aligned with org...

12. [Good Governance Practices for CNCF Projects](https://contribute.cncf.io/resources/videos/2022/good-governance-practices/) - Practical advice to create neutral, fair governance structures and processes for open-source project...

13. [Using OpenTelemetry and the OTel Collector for Logs, Metrics, and ...](https://www.causely.ai/blog/using-opentelemetry-and-the-otel-collector-for-logs-metrics-and-traces) - The OTel Collector acts as a central data pipeline for collecting, processing, and exporting telemet...

14. [OpenTelemetry Signals Overview: Logs vs Metrics vs Traces - Dash0](https://www.dash0.com/knowledge/logs-metrics-and-traces-observability) - Metrics indicate that something is wrong, traces show where it occurred, and logs explain why by cap...

15. [Pushing application metrics to otel-collector - DEV Community](https://dev.to/ashokan/pushing-application-metrics-to-otel-collector-3275) - The push model can be less scalable, as the OpenTelemetry Collector may need to be scaled to handle ...

16. [Telemetry Configuration Guide for Cisco NCS 540 Series Routers ...](https://www.cisco.com/c/en/us/td/docs/iosxr/ncs5xx/telemetry/26xx/b-telemetry-cg-26xx-ncs540/telemetry-introduction.html) - The following image shows the comparative benefits of streaming telemetry data using the telemetry p...

17. [Overview | Prometheus](https://prometheus.io/docs/introduction/overview/) - Components ; the main Prometheus server which scrapes and stores time series data ; a push gateway f...

18. [What You Need to Know About Prometheus Metrics - OpenObserve](https://openobserve.ai/blog/what-you-need-to-know-about-prometheus-architecture/) - In Prometheus, exporters are used to gather metrics from various sources, such as system hardware, a...

19. [Prometheus Monitoring: From Zero to Hero, The Right Way - Dash0](https://www.dash0.com/guides/prometheus-monitoring) - At its core, Prometheus is a time-series database with a powerful query language called PromQL. Its ...

20. [Architecture | OpenTelemetry](https://opentelemetry.io/docs/collector/architecture/) - Pipelines can operate on three telemetry data types: traces, metrics, and logs. The data type is a p...

21. [OpenTelemetry Overview: Unifying Traces, Metrics, and Logs](https://www.dnsstuff.com/opentelemetry-overview-traces-metrics-logs) - Get a complete OpenTelemetry overview: traces, metrics, and logs explained. Learn how OTel unifies o...

22. [1.2: Address Unauthorized Assets](https://controls-assessment-specification.readthedocs.io/en/latest/control-1/control-1.2.html) - Ensure that a process exists to address unauthorized assets on a weekly basis. The enterprise may ch...

23. [CIS Control 01: Inventory and Control of Enterprise Assets - Tripwire](https://www.tripwire.com/state-of-security/cis-control-1) - Description: Ensure that a process exists to address unauthorized assets on a weekly basis. The ente...

24. [What is CSAM in Cyber Security? A Guide For Businesses](https://cmitsolutions.com/blog/what-is-csam-in-cyber-security/) - Learn what CSAM means in cyber security and how asset management helps businesses protect data, ensu...

25. [IT Security Risk and IT Asset Management: What Every IT Leader ...](https://assetloom.com/en/blog/it-security-risk-it-asset-management) - Real-time asset tracking helps identify rogue connections and shadow IT before they create risk. ......

26. [One IT Asset Management Guide to Rule Your Hybrid Cloud Setup](https://cloudaware.com/blog/it-asset-management/) - IT Asset Management — ITAM — is your command center for everything that powers, drains, or breaks yo...

27. [ISO 27001 Controls: Annex A.8 Asset Management - DataGuard](https://www.dataguard.com/blog/iso-27001-annex-a.8-asset-management) - Annex A.8 covers Asset Management and outlines its role in upholding accountability for and assignin...

28. [8 IT Asset Management or ITAM Best Practices Explained - ITSM.tools](https://itsm.tools/itam-best-practices/) - It should cover all asset types, including hardware, software, cloud resources, and digital assets. ...

29. [SP 1800-5, IT Asset Management | CSRC](https://csrc.nist.gov/pubs/sp/1800/5/final) - An effective IT asset management (ITAM) solution can tie together physical and virtual assets and pr...

30. [Understanding ISO 27001:2022 Annex A.8 – Asset Management](https://www.sorinmustaca.com/understanding-iso-27001-2022-annex-a-8-asset-management/) - ISO 27001:2022 Annex A.8, “Asset Management,” addresses the importance of identifying, classifying, ...

31. [Monitoring Golang Services with Prometheus: Choosing Between ...](https://hackernoon.com/monitoring-golang-services-with-prometheus-choosing-between-pull-and-push-models) - Discover how Prometheus collects metrics, why the pull model is preferred, and when to use the push ...

32. [Why is Prometheus Pull-Based? - DEV Community](https://dev.to/mikkergimenez/why-is-prometheus-pull-based-36k1) - Being pull-based means that the prometheus server pulls metrics from targets (your infrastructure an...

