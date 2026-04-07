// Package errors provides a structured error catalog for kite-collector.
// Each error has a unique code (KITE-Ennnn), a human-readable message,
// an explanation of the likely cause, and OS-specific remediation steps.
package errors

import (
	"fmt"
	"runtime"
	"slices"
	"strings"
)

// KiteError represents a catalogued error with structured remediation.
// Fields ordered map-first to minimise GC pointer bitmap (fieldalignment).
type KiteError struct {
	// Remediation maps runtime.GOOS values to OS-specific fix instructions.
	// The key "default" is used as a fallback when no OS-specific entry exists.
	Remediation map[string]string
	// Code is the unique identifier, e.g. "KITE-E001".
	Code string
	// Message is a short human-readable summary.
	Message string
	// Cause explains why this error typically occurs.
	Cause string
}

// RemediationFor returns the remediation text appropriate for the given OS.
// Falls back to "default" if no OS-specific entry exists.
func (e KiteError) RemediationFor(goos string) string {
	if r, ok := e.Remediation[goos]; ok {
		return r
	}
	return e.Remediation["default"]
}

// Format returns a multi-line human-readable representation of the error.
func (e KiteError) Format() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Error:       %s\n", e.Code)
	fmt.Fprintf(&b, "Message:     %s\n", e.Message)
	fmt.Fprintf(&b, "Cause:       %s\n", e.Cause)
	fmt.Fprintf(&b, "Fix (%s):\n", runtime.GOOS)
	fmt.Fprintf(&b, "%s\n", e.RemediationFor(runtime.GOOS))
	return b.String()
}

// Lookup returns the KiteError for the given code, or nil if not found.
func Lookup(code string) *KiteError {
	code = strings.ToUpper(strings.TrimSpace(code))
	e, ok := Catalog[code]
	if !ok {
		return nil
	}
	return &e
}

// Codes returns all error codes in sorted order.
func Codes() []string {
	codes := make([]string, 0, len(Catalog))
	for code := range Catalog {
		codes = append(codes, code)
	}
	slices.Sort(codes)
	return codes
}

// Catalog is the authoritative map of all kite-collector error codes.
var Catalog = map[string]KiteError{
	"KITE-E001": {
		Code:    "KITE-E001",
		Message: "Docker not accessible",
		Cause:   "kite-collector could not connect to the Docker daemon.",
		Remediation: map[string]string{
			"linux":   "Ensure Docker is running: sudo systemctl start docker\nAdd your user to the docker group: sudo usermod -aG docker $USER\nThen log out and back in.",
			"darwin":  "Ensure Docker Desktop is running. Check the menu bar icon.\nIf installed via Homebrew: brew services start docker",
			"windows": "Ensure Docker Desktop is running.\nCheck Settings > General > 'Expose daemon on tcp://localhost:2375'\nOr verify the named pipe exists: dir //./pipe/docker_engine",
			"default": "Ensure the Docker daemon is running and accessible.",
		},
	},
	"KITE-E002": {
		Code:    "KITE-E002",
		Message: "Wazuh authentication failed",
		Cause:   "Could not authenticate to the Wazuh Manager API.",
		Remediation: map[string]string{
			"default": "Check KITE_WAZUH_USERNAME and KITE_WAZUH_PASSWORD environment variables.\nDefault credentials: wazuh:wazuh\nVerify the API is reachable: curl -k https://localhost:55000/security/user/authenticate",
		},
	},
	"KITE-E003": {
		Code:    "KITE-E003",
		Message: "SQLite database locked",
		Cause:   "Another process has the database file open with an exclusive lock.",
		Remediation: map[string]string{
			"linux":   "Check for other kite-collector or sqlite3 processes:\n  lsof kite.db\n  fuser kite.db\nWait a few seconds and try again.",
			"windows": "Check for other kite-collector or sqlite3 processes in Task Manager.\nClose any open database viewers and try again.",
			"default": "Close any other kite-collector or sqlite3 processes.\nWait a few seconds and try again.",
		},
	},
	"KITE-E004": {
		Code:    "KITE-E004",
		Message: "Network scan timeout",
		Cause:   "One or more hosts in the scan scope did not respond within the timeout.",
		Remediation: map[string]string{
			"default": "Increase timeout in config: discovery.sources.network.timeout\nReduce scope: use /24 instead of /16.\nCheck firewall rules on this host.\nVerify the target network is reachable: ping <target>",
		},
	},
	"KITE-E005": {
		Code:    "KITE-E005",
		Message: "UniFi controller unreachable",
		Cause:   "Could not connect to the UniFi Network controller API.",
		Remediation: map[string]string{
			"default": "Verify the endpoint is correct: KITE_UNIFI_ENDPOINT\nCheck that the controller is running and accessible.\nThe default port is 8443 (HTTPS).\nVerify credentials: KITE_UNIFI_USERNAME and KITE_UNIFI_PASSWORD",
		},
	},
	"KITE-E006": {
		Code:    "KITE-E006",
		Message: "Cloud credentials missing",
		Cause:   "Required cloud provider credentials are not configured.",
		Remediation: map[string]string{
			"linux":   "AWS: export AWS_ACCESS_KEY_ID=... && export AWS_SECRET_ACCESS_KEY=...\nGCP: export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json\nAzure: export AZURE_TENANT_ID=... AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=...",
			"windows": "AWS: set AWS_ACCESS_KEY_ID=... & set AWS_SECRET_ACCESS_KEY=...\nGCP: set GOOGLE_APPLICATION_CREDENTIALS=C:\\path\\to\\key.json\nAzure: set AZURE_TENANT_ID=... & set AZURE_CLIENT_ID=... & set AZURE_CLIENT_SECRET=...",
			"default": "Set the required environment variables for your cloud provider.\nSee: kite-collector help or docs/connectors/ for provider-specific setup.",
		},
	},
	"KITE-E007": {
		Code:    "KITE-E007",
		Message: "Configuration file invalid",
		Cause:   "The YAML configuration file could not be parsed or contains invalid values.",
		Remediation: map[string]string{
			"default": "Check the YAML syntax: look for indentation errors or missing colons.\nValidate with: python3 -c \"import yaml; yaml.safe_load(open('kite-collector.yaml'))\"\nSee configs/kite-collector.example.yaml for a reference.",
		},
	},
	"KITE-E008": {
		Code:    "KITE-E008",
		Message: "Permission denied",
		Cause:   "kite-collector does not have permission to access a required resource.",
		Remediation: map[string]string{
			"linux":   "Check file permissions: ls -la <path>\nFor Docker socket: sudo usermod -aG docker $USER\nFor network scanning: grant CAP_NET_RAW capability or run as root.",
			"darwin":  "Check file permissions: ls -la <path>\nFor Docker: ensure Docker Desktop is running.\nFor network scanning: run with sudo if needed.",
			"windows": "Run kite-collector as Administrator.\nRight-click > Run as Administrator, or use an elevated command prompt.",
			"default": "Ensure the current user has read access to the required resource.",
		},
	},
	"KITE-E009": {
		Code:    "KITE-E009",
		Message: "No discovery sources enabled",
		Cause:   "The configuration has no discovery sources enabled. At least one source is required to run a scan.",
		Remediation: map[string]string{
			"default": "Enable at least one source in your config file:\n  discovery:\n    sources:\n      agent:\n        enabled: true\n\nOr use auto-discovery: kite-collector scan --auto",
		},
	},
	"KITE-E010": {
		Code:    "KITE-E010",
		Message: "Database migration failed",
		Cause:   "The SQLite schema migration could not be applied.",
		Remediation: map[string]string{
			"default": "Check that the database file is not corrupted:\n  sqlite3 kite.db 'PRAGMA integrity_check;'\nIf corrupted, delete the file and re-scan to rebuild:\n  rm kite.db && kite-collector scan\nBackup the file before deleting if it contains important data.",
		},
	},
	"KITE-E011": {
		Code:    "KITE-E011",
		Message: "Panic recovered",
		Cause:   "A Go panic was caught by the recovery middleware. The process continued operating but the operation that panicked was aborted.",
		Remediation: map[string]string{
			"default": "Check the structured error log for the full stack trace.\nIdentify the component that panicked from the 'component' field.\nReport the issue with the stack trace to the development team.\nIf the panic recurs, the circuit breaker will temporarily disable the affected source.",
		},
	},
	"KITE-E012": {
		Code:    "KITE-E012",
		Message: "Circuit breaker tripped",
		Cause:   "A discovery source has been disabled after repeated consecutive failures. It will be retried automatically after the cooldown period.",
		Remediation: map[string]string{
			"default": "Check the source health via GET /api/v1/source-health.\nReview logs for the specific failure reason.\nVerify connectivity to the upstream API or service.\nThe source will be retried automatically after the cooldown (default: 5 minutes).\nTo adjust thresholds: safety.circuit_breaker.failure_threshold in kite-collector.yaml.",
		},
	},
	"KITE-E013": {
		Code:    "KITE-E013",
		Message: "Scan deadline exceeded",
		Cause:   "The scan did not complete within the configured deadline. Partial results were saved but some phases (software collection, auditing, stale-asset detection) may have been skipped.",
		Remediation: map[string]string{
			"default": "Increase the deadline: safety.scan_deadline in kite-collector.yaml (default: 30m).\nReduce scan scope: disable slow sources or narrow CIDR ranges.\nCheck source latency: sources behind high-latency networks increase scan time.\nReview the scan result status for which phases completed.",
		},
	},
	"KITE-E014": {
		Code:    "KITE-E014",
		Message: "Response truncated",
		Cause:   "An HTTP response exceeded the maximum allowed size and was truncated. The client received a partial response body.",
		Remediation: map[string]string{
			"default": "Use pagination parameters (limit, offset) to request smaller result sets.\nIncrease the limit if needed: safety.max_response_bytes in kite-collector.yaml (default: 10 MB).\nFilter results using query parameters to reduce response size.",
		},
	},
	"KITE-E015": {
		Code:    "KITE-E015",
		Message: "Request body too large",
		Cause:   "An incoming HTTP request body exceeded the maximum allowed size and was rejected.",
		Remediation: map[string]string{
			"default": "Reduce the size of the request payload.\nIncrease the limit if needed: safety.max_request_bytes in kite-collector.yaml (default: 1 MB).\nFor bulk operations, split large payloads into multiple smaller requests.",
		},
	},
}
