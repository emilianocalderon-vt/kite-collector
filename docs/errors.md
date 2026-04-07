# Error Catalog

kite-collector uses structured error codes for common problems. Each error includes a code, message, likely cause, and OS-specific remediation steps.

Look up an error from the CLI:

```bash
kite-collector error KITE-E001
kite-collector error --list
```

## Error codes

### KITE-E001: Docker not accessible

**Cause:** kite-collector could not connect to the Docker daemon.

**Fix (Linux):**
```bash
sudo systemctl start docker
sudo usermod -aG docker $USER
# Log out and back in
```

**Fix (macOS):**
Ensure Docker Desktop is running. Check the menu bar icon.

**Fix (Windows):**
Ensure Docker Desktop is running. Check Settings > General > "Expose daemon on tcp://localhost:2375". Or verify the named pipe: `dir //./pipe/docker_engine`

---

### KITE-E002: Wazuh authentication failed

**Cause:** Could not authenticate to the Wazuh Manager API.

**Fix:**
```bash
# Check credentials
export KITE_WAZUH_USERNAME=wazuh
export KITE_WAZUH_PASSWORD=wazuh

# Verify API is reachable
curl -k https://localhost:55000/security/user/authenticate
```

---

### KITE-E003: SQLite database locked

**Cause:** Another process has the database file open with an exclusive lock.

**Fix (Linux):**
```bash
lsof kite.db
fuser kite.db
```

**Fix (Windows):**
Check Task Manager for other kite-collector or sqlite3 processes.

---

### KITE-E004: Network scan timeout

**Cause:** One or more hosts did not respond within the timeout.

**Fix:**
- Increase timeout in config: `discovery.sources.network.timeout`
- Reduce scope: use `/24` instead of `/16`
- Check firewall rules on this host

---

### KITE-E005: UniFi controller unreachable

**Cause:** Could not connect to the UniFi Network controller API.

**Fix:**
- Verify endpoint: `KITE_UNIFI_ENDPOINT`
- Default port is 8443 (HTTPS)
- Check credentials: `KITE_UNIFI_USERNAME` and `KITE_UNIFI_PASSWORD`

---

### KITE-E006: Cloud credentials missing

**Cause:** Required cloud provider credentials are not configured.

**Fix (Linux/macOS):**
```bash
# AWS
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...

# GCP
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json

# Azure
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
```

**Fix (Windows CMD):**
```cmd
set AWS_ACCESS_KEY_ID=...
set AWS_SECRET_ACCESS_KEY=...
```

---

### KITE-E007: Configuration file invalid

**Cause:** The YAML configuration file could not be parsed.

**Fix:**
- Check YAML syntax for indentation errors or missing colons
- Validate: `python3 -c "import yaml; yaml.safe_load(open('kite-collector.yaml'))"`
- See `configs/kite-collector.example.yaml` for reference

---

### KITE-E008: Permission denied

**Cause:** kite-collector does not have permission to access a required resource.

**Fix (Linux):**
```bash
# Docker socket
sudo usermod -aG docker $USER

# Network scanning
sudo setcap cap_net_raw+ep ./kite-collector
```

**Fix (Windows):**
Run as Administrator (right-click > Run as Administrator).

---

### KITE-E009: No discovery sources enabled

**Cause:** No discovery sources are enabled in the configuration.

**Fix:**
```yaml
# Enable at least one source in kite-collector.yaml:
discovery:
  sources:
    agent:
      enabled: true
```

Or use auto-discovery: `kite-collector scan --auto`

---

### KITE-E010: Database migration failed

**Cause:** The SQLite schema migration could not be applied.

**Fix:**
```bash
# Check database integrity
sqlite3 kite.db 'PRAGMA integrity_check;'

# If corrupted, delete and re-scan
rm kite.db
kite-collector scan
```
