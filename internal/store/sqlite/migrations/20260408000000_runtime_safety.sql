-- Runtime safety tables for kite-collector.
-- Adds circuit breaker state tracking and runtime incident logging.

-- Circuit breaker state per discovery source.
CREATE TABLE IF NOT EXISTS source_health (
    source_name   TEXT PRIMARY KEY,
    state         TEXT NOT NULL DEFAULT 'healthy'
                  CHECK (state IN ('healthy', 'degraded', 'open')),
    consecutive_failures  INTEGER NOT NULL DEFAULT 0,
    consecutive_successes INTEGER NOT NULL DEFAULT 0,
    failure_threshold     INTEGER NOT NULL DEFAULT 3,
    cooldown_seconds      INTEGER NOT NULL DEFAULT 300,
    last_success_at       TEXT,
    last_failure_at       TEXT,
    last_failure_reason   TEXT,
    total_trips           INTEGER NOT NULL DEFAULT 0,
    updated_at            TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Runtime incidents (panic recoveries, timeouts, circuit trips).
CREATE TABLE IF NOT EXISTS runtime_incidents (
    id              TEXT PRIMARY KEY,
    incident_type   TEXT NOT NULL
                    CHECK (incident_type IN (
                        'panic_recovered', 'timeout_exceeded',
                        'circuit_breaker_tripped', 'response_truncated',
                        'body_limit_exceeded'
                    )),
    component       TEXT NOT NULL,
    error_message   TEXT NOT NULL,
    stack_trace     TEXT,
    scan_run_id     TEXT,
    severity        TEXT NOT NULL DEFAULT 'high'
                    CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    recovered       INTEGER NOT NULL DEFAULT 1,
    error_code      TEXT,
    created_at      TEXT NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
);

CREATE INDEX IF NOT EXISTS idx_incidents_scan ON runtime_incidents(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_incidents_type ON runtime_incidents(incident_type);
CREATE INDEX IF NOT EXISTS idx_incidents_component ON runtime_incidents(component);
