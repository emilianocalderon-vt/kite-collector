# SQLite Cheatsheet

Quick reference for querying kite-collector's SQLite database.

## Quick start

```bash
# Use the built-in query command (no sqlite3 needed)
kite-collector query assets
kite-collector query software --limit 20
kite-collector query findings --severity high
kite-collector query scans

# Or open the SQLite shell with table formatting
kite-collector db
```

## Common queries

### List all assets

```sql
SELECT hostname, asset_type, is_authorized, is_managed, last_seen_at
FROM assets
ORDER BY last_seen_at DESC;
```

### Software with CVE-matching CPE

```sql
SELECT software_name, version, cpe23
FROM installed_software
WHERE cpe23 != ''
LIMIT 20;
```

### Security findings by severity

```sql
SELECT severity, count(*) as total
FROM config_findings
GROUP BY severity
ORDER BY CASE severity
  WHEN 'critical' THEN 1
  WHEN 'high' THEN 2
  WHEN 'medium' THEN 3
  WHEN 'low' THEN 4
  ELSE 5
END;
```

### Assets not seen in 7 days

```sql
SELECT hostname, asset_type, last_seen_at
FROM assets
WHERE last_seen_at < datetime('now', '-7 days')
ORDER BY last_seen_at;
```

### Unauthorized assets

```sql
SELECT hostname, asset_type, discovery_source, first_seen_at
FROM assets
WHERE is_authorized = 'unauthorized'
ORDER BY first_seen_at DESC;
```

### Unmanaged assets

```sql
SELECT hostname, asset_type, os_family, discovery_source
FROM assets
WHERE is_managed = 'unmanaged';
```

### Join assets with their software count

```sql
SELECT a.hostname, a.asset_type, count(s.id) as packages
FROM assets a
LEFT JOIN installed_software s ON s.asset_id = a.id
GROUP BY a.hostname, a.asset_type
ORDER BY packages DESC;
```

### Findings with CWE details

```sql
SELECT check_id, severity, cwe_id, title
FROM config_findings
ORDER BY CASE severity
  WHEN 'critical' THEN 1
  WHEN 'high' THEN 2
  WHEN 'medium' THEN 3
  ELSE 4
END;
```

### Posture assessments (CAPEC patterns)

```sql
SELECT capec_id, likelihood, mitigation
FROM posture_assessments
ORDER BY CASE likelihood
  WHEN 'high' THEN 1
  WHEN 'medium' THEN 2
  WHEN 'low' THEN 3
  ELSE 4
END;
```

### Scan history

```sql
SELECT started_at, status, total_assets, new_assets, stale_assets, coverage_percent
FROM scan_runs
ORDER BY started_at DESC
LIMIT 10;
```

### Assets discovered per source

```sql
SELECT discovery_source, count(*) as total
FROM assets
GROUP BY discovery_source
ORDER BY total DESC;
```

### Network interfaces with public IPs

```sql
SELECT a.hostname, n.ip_address, n.mac_address, n.is_public
FROM network_interfaces n
JOIN assets a ON a.id = n.asset_id
WHERE n.is_public = 1;
```

## SQLite shell tips

```
.mode table        -- formatted table output
.mode csv          -- CSV output
.mode json         -- JSON output
.headers on        -- show column headers
.schema assets     -- show table schema
.tables            -- list all tables
.quit              -- exit
```

## Export to CSV

```bash
# Using the query command
kite-collector query assets > assets.csv

# Using sqlite3 directly
sqlite3 -header -csv data/kite.db "SELECT * FROM assets" > assets.csv
```

## Database schema

The database contains these tables:

| Table | Description |
|-------|-------------|
| `assets` | Discovered assets (hostname, type, classification) |
| `network_interfaces` | IP/MAC addresses per asset |
| `installed_software` | Packages with CPE identifiers |
| `scan_runs` | Scan history with coverage metrics |
| `events` | Asset lifecycle events |
| `config_findings` | Security audit results (CWE mapped) |
| `posture_assessments` | CAPEC attack pattern analysis |
