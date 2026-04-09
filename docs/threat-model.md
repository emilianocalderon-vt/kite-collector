# Threat Model — kite-collector

Derived from the current codebase. Last updated: 2026-04-07.

---

## 1. What we protect

| Asset | Location | Impact if compromised |
|-------|----------|----------------------|
| Asset inventory (hostnames, IPs, MACs, OS) | SQLite, OTLP stream, PostgreSQL | Attacker gets a full network map |
| Software versions + CPE identifiers | SQLite, OTLP stream | Attacker knows exactly what to exploit |
| Config audit findings (CWE-mapped) | SQLite, OTLP stream | A ready-made list of weaknesses |
| Agent Ed25519 private key | TPM / keyring / file | Impersonate the agent, forge events |
| mTLS client certificate | Filesystem (`agent.pem`) | Authenticate as the agent to the SaaS |
| CA certificate chain | Filesystem (`ca.pem`) | Trust anchor for the agent-to-SaaS channel |
| Discovery source credentials | Environment variables only | Access to customer's cloud/MDM/CMDB APIs |
| Customer network topology | Inferred from scan scope + results | Lateral movement roadmap |
| Enrollment token | Passed at first boot | Register rogue agents against the SaaS |

---

## 2. Trust boundaries

```
┌──────────────────────────────────────────────────────┐
│ Customer host                                        │
│                                                      │
│  ┌─────────────┐   ┌───────────┐   ┌─────────────┐  │
│  │ kite-collector│──│ SQLite DB │   │ identity/   │  │
│  │ (agent)     │   │ (kite.db) │   │ keys + certs│  │
│  └──────┬──────┘   └───────────┘   └─────────────┘  │
│         │                                            │
│         │ mTLS (OTLP /v1/logs + gRPC)                │
└─────────┼────────────────────────────────────────────┘
          │  ← BOUNDARY: untrusted network
┌─────────┼────────────────────────────────────────────┐
│ SaaS    │                                            │
│  ┌──────┴──────┐   ┌────────────┐   ┌────────────┐  │
│  │ OTel        │──▶│ Log backend│   │ Enrollment │  │
│  │ Collector   │   │ (Loki/ES)  │   │ service    │  │
│  └─────────────┘   └────────────┘   └────────────┘  │
│                                                      │
│  All customer data converges here                    │
└──────────────────────────────────────────────────────┘
```

Three trust boundaries:

1. **Agent ↔ Host OS** — the agent reads system files, network state, and env vars from the host it runs on.
2. **Agent ↔ Network** — OTLP events and gRPC RPCs cross untrusted networks to reach the SaaS.
3. **SaaS perimeter** — the SaaS holds aggregated data from every customer.

---

## 3. Threat actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| **Compromised host** | Root on the machine running kite | Read collected data, steal agent identity, tamper with events |
| **Network attacker** | Intercept/modify traffic between agent and SaaS | Eavesdrop on asset data, inject fake events, block alerts |
| **Malicious insider (customer)** | Legitimate access to the host | Suppress `UnauthorizedAssetDetected` events, hide rogue devices |
| **Supply chain attacker** | Compromise the kite binary before deployment | Exfiltrate data via modified agent, backdoor customer networks |
| **SaaS breach** | Access to the backend that stores all customers' data | Mass exfiltration of network maps, software inventories, weaknesses |
| **Rogue enrollment** | Stolen enrollment token | Register fake agents, inject false asset data into the SaaS |

---

## 4. Attack surface analysis

### 4.1 Identity and key storage (`internal/identity/`)

| Threat | Current mitigation | Residual risk |
|--------|--------------------|---------------|
| Private key stolen from disk | TPM seals key to hardware; keyring stores in kernel memory; file backend uses mode 0600 | **File backend**: key sits next to data it protects — disk theft defeats both. Only TPM/keyring provide real protection |
| Key extracted from process memory | None | Keys in memory during operation regardless of backend |
| Agent identity cloned to another machine | TPM keys are non-exportable; machine fingerprint sent at enrollment | Machine fingerprint (`/etc/machine-id`) easily spoofed — no cryptographic hardware binding outside TPM |

### 4.2 Enrollment (`internal/enrollment/`)

| Threat | Current mitigation | Residual risk |
|--------|--------------------|---------------|
| MITM at first enrollment | Bootstrap TLS with system CA or custom CA file | **No server cert pinning until after enrollment completes** — first connection is TOFU |
| Enrollment token stolen | Token used once, passed via env var | Token in env var visible via `/proc/<pid>/environ` on Linux |
| Rogue agent registered | Token required | Tokens are long-lived; no rate limiting or attestation |
| Certificate issuance to wrong agent | Server checks enrollment token + agent ID | No hardware attestation — any process with the token can enroll |

**Certificate storage permissions (as implemented):**

| File | Mode | Issue |
|------|------|-------|
| `ca.pem` | 0644 | World-readable — exposes trust chain |
| `agent.pem` | 0644 | World-readable — exposes agent identity |
| `agent-key.pem` | 0600 | Correct — but defeated by privilege escalation |

### 4.3 Transport — OTLP emitter (`internal/emitter/otlp.go`)

| Threat | Current mitigation | Residual risk |
|--------|--------------------|---------------|
| Eavesdrop on asset events | mTLS when configured | **HTTP plaintext is allowed** — misconfiguration sends full inventory unencrypted |
| Fake events injected | mTLS client cert authenticates agent | **No per-event signing** — a compromised host can modify events after generation but before emission |
| Event suppression | None | Local attacker or proxy can drop events silently; SaaS cannot distinguish "no events" from "events blocked" |
| Replay events | No nonce or sequence number | Old events re-sent to pollute inventory |

### 4.4 Transport — gRPC (`api/grpc/proto/`)

| Threat | Current mitigation | Residual risk |
|--------|--------------------|---------------|
| MITM on gRPC channel | mTLS + TOFU pinning + channel binding (RFC 9266) | Channel binding only effective with TLS 1.3; TOFU vulnerable on first connect |
| TLS-terminating proxy undetected | Channel binding detects keying material mismatch | Requires both sides to implement verification |
| Oversized streaming RPC | None specified | No per-message size limit on `ReportAssets` / `ReportFindings` streams |

### 4.5 Data at rest — SQLite / PostgreSQL (`internal/store/`)

| Threat | Current mitigation | Residual risk |
|--------|--------------------|---------------|
| SQLite file read by local attacker | File mode 0600 | **No encryption at rest** — `kite.db` is plaintext; any root user or disk theft exposes full inventory |
| PostgreSQL credentials leaked | DSN in env var, not config file | Env var visible in `/proc`; DSN may contain password |
| Stale data accumulates | Configurable stale threshold (default 7 days) | Old data not purged from DB — historical inventory accessible indefinitely |

### 4.6 Discovery sources (`internal/discovery/`, `internal/engine/`)

| Threat | Current mitigation | Residual risk |
|--------|--------------------|---------------|
| Source credentials leaked | Env vars only, never in config or logs | `/proc/<pid>/environ` readable by root; credentials in process memory |
| SSRF via scan scope | Config validation checks CIDR format | **No blocklist** — `169.254.169.254/32` (cloud metadata), `fd00::/8`, link-local addresses scannable |
| Partial scan reported as complete | Circuit breaker + scan deadline; partial results accepted | Operator may not notice missing sources — no explicit "coverage gap" alert |

### 4.7 Configuration audit (`internal/audit/`)

| Threat | Current mitigation | Residual risk |
|--------|--------------------|---------------|
| Sensitive config details sent to SaaS | Findings contain rule IDs and descriptions, not raw file contents | Finding titles/details may reveal security posture ("SSH root login enabled") to anyone with SaaS access |
| Auditor requires root | Graceful degradation — skips checks without permission | Silent failure means incomplete audit with no warning |

### 4.8 Agent binary and supply chain

| Threat | Current mitigation | Residual risk |
|--------|--------------------|---------------|
| Tampered binary deployed | `CGO_ENABLED=0`, distroless container | **No binary signing, no SBOM, no SLSA provenance** — customer cannot verify authenticity |
| Dependency compromise | `go.sum` integrity check at build time | No runtime verification; compromised dependency ships in binary |

---

## 5. Risk summary

### Critical

| # | Risk | Why critical |
|---|------|-------------|
| C1 | **No binary signing or SBOM** | Customers cannot verify the binary is authentic. Blocks enterprise/government adoption. |
| C2 | **SaaS is a single point of breach** | All customers' network maps, software inventories, and security weaknesses in one place. |
| C3 | **SQLite unencrypted at rest** | Disk theft or local privilege escalation exposes full asset inventory + audit findings. |

### High

| # | Risk | Why high |
|---|------|----------|
| H1 | Enrollment MITM on first connect | No server cert pinning until enrollment completes — network attacker can intercept bootstrap. |
| H2 | File backend stores private key in plaintext | Defeats all downstream protections (mTLS, event integrity) on disk theft. |
| H3 | OTLP allows plaintext HTTP | Misconfiguration sends full inventory unencrypted across the network. |
| H4 | No event signing | Compromised host can modify or suppress events before they reach the SaaS. |
| H5 | CA and agent certs world-readable (0644) | Information disclosure on shared or multi-tenant hosts. |
| H6 | Credentials in env vars visible via `/proc` | Local attacker reads cloud/MDM/CMDB credentials. |

### Medium

| # | Risk | Why medium |
|---|------|-----------|
| M1 | No SSRF blocklist for scan scope | Cloud metadata endpoint (`169.254.169.254`) reachable via network scanner. |
| M2 | No certificate revocation checking | Compromised agent cert cannot be revoked — stays valid until expiry. |
| M3 | Machine fingerprint spoofable | No cryptographic binding to hardware outside TPM path. |
| M4 | No per-event replay protection | Old events can be re-sent to pollute the inventory. |
| M5 | Partial scan results accepted silently | Missing assets from flaky sources not surfaced to operator. |

### Low

| # | Risk | Why low |
|---|------|---------|
| L1 | Keyring keys lost on logout | Session keyring cleared — unsuitable for long-running services without user session. |
| L2 | Audit findings reveal security posture | By design, but a concern if SaaS is breached. |
| L3 | Stale data not purged | Historical asset records remain accessible indefinitely. |

---

## 6. Recommended mitigations

| Risk | Mitigation | Effort |
|------|-----------|--------|
| C1 | Sign releases with Sigstore/cosign, generate SBOM with `syft`, publish SLSA provenance via GitHub Actions | Medium |
| C2 | Tenant isolation in backend, per-customer encryption keys, audit logging on all data access | High |
| C3 | Derive AES-256 key via HKDF from agent private key (TPM/keyring), encrypt SQLite with SQLCipher | Medium |
| H1 | Ship a pinned CA fingerprint in the enrollment token or embed it in the binary | Low |
| H2 | Enforce `key_backend: tpm` or `keyring` at enrollment; reject file-only agents in SaaS | Low |
| H3 | Remove plaintext HTTP option from OTLP emitter; require TLS unconditionally | Low |
| H4 | HMAC or Ed25519 signature on each OTLP payload using the agent's private key | Medium |
| H5 | Change `ca.pem` and `agent.pem` to mode 0600 | Trivial |
| H6 | Read credentials from a secrets file (mode 0600) instead of env vars, or integrate with a secret manager | Low |
| M1 | Blocklist RFC 6890 special-purpose addresses in network scanner | Low |
| M2 | Implement OCSP stapling or short-lived certs (hours, not days) with forced renewal | Medium |
| M3 | Require TPM attestation at enrollment for high-security deployments | High |
| M4 | Add monotonic sequence number per agent, verified server-side | Low |
| M5 | Emit explicit `SourceUnavailable` event when a source is skipped | Low |
