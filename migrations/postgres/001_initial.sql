-- migrations/postgres/001_initial.sql
-- kite-collector asset discovery schema (PostgreSQL)

CREATE TABLE IF NOT EXISTS assets (
    id               UUID PRIMARY KEY,
    asset_type       TEXT NOT NULL CHECK(asset_type IN ('server','workstation','network_device','cloud_instance','container','virtual_machine','iot_device','appliance')),
    hostname         TEXT NOT NULL,
    os_family        TEXT,
    os_version       TEXT,
    is_authorized    TEXT NOT NULL DEFAULT 'unknown' CHECK(is_authorized IN ('unknown','authorized','unauthorized')),
    is_managed       TEXT NOT NULL DEFAULT 'unknown' CHECK(is_managed IN ('unknown','managed','unmanaged')),
    environment      TEXT,
    owner            TEXT,
    criticality      TEXT,
    discovery_source TEXT NOT NULL,
    first_seen_at    TIMESTAMPTZ NOT NULL,
    last_seen_at     TIMESTAMPTZ NOT NULL,
    tags             JSONB,
    natural_key      TEXT,
    UNIQUE(hostname, asset_type)
);

CREATE TABLE IF NOT EXISTS network_interfaces (
    id             UUID PRIMARY KEY,
    asset_id       UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    interface_name TEXT,
    ip_address     TEXT NOT NULL,
    mac_address    TEXT,
    subnet         TEXT,
    is_primary     BOOLEAN NOT NULL DEFAULT FALSE,
    is_public      BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS installed_software (
    id              UUID PRIMARY KEY,
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    software_name   TEXT NOT NULL,
    vendor          TEXT NOT NULL DEFAULT '',
    version         TEXT NOT NULL,
    cpe23           TEXT,
    package_manager TEXT
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id                UUID PRIMARY KEY,
    started_at        TIMESTAMPTZ NOT NULL,
    completed_at      TIMESTAMPTZ,
    status            TEXT NOT NULL DEFAULT 'running',
    total_assets      INTEGER DEFAULT 0,
    new_assets        INTEGER DEFAULT 0,
    updated_assets    INTEGER DEFAULT 0,
    stale_assets      INTEGER DEFAULT 0,
    coverage_percent  DOUBLE PRECISION DEFAULT 0.0,
    error_count       INTEGER DEFAULT 0,
    scope_config      JSONB,
    discovery_sources JSONB
);

CREATE TABLE IF NOT EXISTS events (
    id          UUID PRIMARY KEY,
    event_type  TEXT NOT NULL CHECK(event_type IN ('AssetDiscovered','AssetUpdated','UnauthorizedAssetDetected','UnmanagedAssetDetected','AssetNotSeen','AssetRemoved')),
    asset_id    UUID NOT NULL REFERENCES assets(id),
    scan_run_id UUID NOT NULL REFERENCES scan_runs(id),
    severity    TEXT NOT NULL DEFAULT 'low',
    details     JSONB,
    timestamp   TIMESTAMPTZ NOT NULL
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_assets_authorized ON assets(is_authorized);
CREATE INDEX IF NOT EXISTS idx_assets_natural_key ON assets(natural_key);
CREATE INDEX IF NOT EXISTS idx_interfaces_ip ON network_interfaces(ip_address);
CREATE INDEX IF NOT EXISTS idx_interfaces_mac ON network_interfaces(mac_address);
CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_asset ON events(asset_id);
CREATE INDEX IF NOT EXISTS idx_software_cpe ON installed_software(cpe23);
