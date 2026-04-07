-- 003_posture_assessments.sql: posture assessment results

CREATE TABLE IF NOT EXISTS posture_assessments (
    id          TEXT PRIMARY KEY,
    asset_id    TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id),
    capec_id    TEXT NOT NULL,
    capec_name  TEXT NOT NULL,
    finding_ids TEXT NOT NULL DEFAULT '[]',
    likelihood  TEXT NOT NULL DEFAULT 'low',
    mitigation  TEXT NOT NULL DEFAULT '',
    timestamp   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_posture_asset ON posture_assessments(asset_id);
CREATE INDEX IF NOT EXISTS idx_posture_capec ON posture_assessments(capec_id);
