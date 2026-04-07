-- 002_config_findings.sql: configuration audit findings

CREATE TABLE IF NOT EXISTS config_findings (
    id          TEXT PRIMARY KEY,
    asset_id    TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id),
    auditor     TEXT NOT NULL,
    check_id    TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'low',
    cwe_id      TEXT NOT NULL,
    cwe_name    TEXT NOT NULL,
    evidence    TEXT NOT NULL,
    expected    TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    cis_control TEXT NOT NULL DEFAULT '',
    timestamp   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_asset ON config_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_cwe ON config_findings(cwe_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON config_findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_check ON config_findings(check_id);
