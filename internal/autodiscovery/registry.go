// Package autodiscovery detects infrastructure services reachable from the
// local host.  It probes sockets, TCP ports, Docker containers, and
// environment variables to build a list of discovered services that
// kite-collector can scan automatically.
//
// All probes are read-only: they never send credentials, write data, or
// modify the discovered systems.
package autodiscovery

// ServiceSignature describes how to detect and confirm a known infrastructure
// service.
// ServiceSignature fields are ordered strings-first, slices-second, scalars-
// last to minimise GC pointer bitmap overhead (fieldalignment).
type ServiceSignature struct {
	// Name is a stable, lowercase identifier (e.g. "wazuh").
	Name string
	// DisplayName is a human-readable label (e.g. "Wazuh Manager").
	DisplayName string
	// FingerprintPath is the HTTP path to GET for identity confirmation.
	FingerprintPath string
	// FingerprintMatch is a substring that must appear in the response
	// body or headers to confirm the service.
	FingerprintMatch string
	// SetupHint is a human-readable instruction shown when the service
	// needs credentials.
	SetupHint string
	// DefaultPorts lists the TCP ports the service typically listens on.
	DefaultPorts []int
	// SocketPaths lists Unix socket paths to check. Use %d for the
	// current user's UID (rootless Podman).
	SocketPaths []string
	// DockerImages lists image name prefixes to match running containers.
	DockerImages []string
	// DockerNames lists container name substrings to match.
	DockerNames []string
	// EnvVars lists environment variables whose presence indicates the
	// service endpoint is pre-configured.
	EnvVars []string
	// CredentialEnvs lists environment variables required to authenticate.
	// When all are set, the service status is "ready"; otherwise
	// "needs_credentials".
	CredentialEnvs []string
	// TLS indicates whether the fingerprint endpoint uses HTTPS.
	TLS bool
}

// KnownServices is the static registry of infrastructure services that
// autodiscovery can detect.
var KnownServices = []ServiceSignature{
	{
		Name:             "docker",
		DisplayName:      "Docker Engine",
		SocketPaths:      []string{"/var/run/docker.sock"},
		FingerprintPath:  "/v1.43/version",
		FingerprintMatch: "ApiVersion",
		SetupHint:        "Ready -- Docker socket accessible.",
	},
	{
		Name:             "podman",
		DisplayName:      "Podman",
		SocketPaths:      []string{"/run/podman/podman.sock", "/run/user/%d/podman/podman.sock"},
		FingerprintPath:  "/v4.0.0/libpod/version",
		FingerprintMatch: "ApiVersion",
		SetupHint:        "Ready -- Podman socket accessible.",
	},
	{
		Name:             "wazuh",
		DisplayName:      "Wazuh Manager",
		DefaultPorts:     []int{55000},
		DockerImages:     []string{"wazuh/wazuh-manager"},
		DockerNames:      []string{"wazuh-manager", "wazuh.manager"},
		FingerprintPath:  "/",
		FingerprintMatch: "Wazuh API REST",
		CredentialEnvs:   []string{"KITE_WAZUH_USERNAME", "KITE_WAZUH_PASSWORD"},
		SetupHint:        "export KITE_WAZUH_USERNAME=admin KITE_WAZUH_PASSWORD=...",
		TLS:              true,
	},
	{
		Name:             "unifi",
		DisplayName:      "UniFi Controller",
		DefaultPorts:     []int{8443, 443},
		DockerImages:     []string{"linuxserver/unifi-controller", "jacobalberty/unifi"},
		DockerNames:      []string{"unifi", "unifi-controller"},
		FingerprintPath:  "/manage",
		FingerprintMatch: "UniFi Network",
		EnvVars:          []string{"KITE_UNIFI_ENDPOINT"},
		CredentialEnvs:   []string{"KITE_UNIFI_API_KEY"},
		SetupHint:        "export KITE_UNIFI_API_KEY=... (from unifi.ui.com -> API Keys)",
		TLS:              true,
	},
	{
		Name:             "proxmox",
		DisplayName:      "Proxmox VE",
		DefaultPorts:     []int{8006},
		FingerprintPath:  "/api2/json/version",
		FingerprintMatch: "pveversion",
		CredentialEnvs:   []string{"KITE_PROXMOX_TOKEN_ID", "KITE_PROXMOX_TOKEN_SECRET"},
		SetupHint:        "export KITE_PROXMOX_TOKEN_ID=user@pam!kite KITE_PROXMOX_TOKEN_SECRET=...",
		TLS:              true,
	},
	{
		Name:             "coolify",
		DisplayName:      "Coolify",
		DefaultPorts:     []int{8000, 3000},
		DockerImages:     []string{"coollabsio/coolify"},
		DockerNames:      []string{"coolify"},
		FingerprintPath:  "/api/v1/version",
		FingerprintMatch: "coolify",
		CredentialEnvs:   []string{"KITE_COOLIFY_TOKEN"},
		SetupHint:        "export KITE_COOLIFY_TOKEN=... (from Coolify -> API Tokens)",
	},
	{
		Name:             "clickhouse",
		DisplayName:      "ClickHouse",
		DefaultPorts:     []int{8123},
		DockerImages:     []string{"clickhouse/clickhouse-server"},
		DockerNames:      []string{"clickhouse"},
		FingerprintPath:  "/ping",
		FingerprintMatch: "Ok",
		SetupHint:        "Ready -- ClickHouse accessible (no auth required for read).",
	},
	{
		Name:             "prometheus",
		DisplayName:      "Prometheus",
		DefaultPorts:     []int{9090},
		DockerImages:     []string{"prom/prometheus"},
		FingerprintPath:  "/-/healthy",
		FingerprintMatch: "Healthy",
		SetupHint:        "Ready -- Prometheus accessible.",
	},
	{
		Name:             "grafana",
		DisplayName:      "Grafana",
		DefaultPorts:     []int{3000},
		DockerImages:     []string{"grafana/grafana"},
		FingerprintPath:  "/api/health",
		FingerprintMatch: "ok",
		SetupHint:        "Ready -- Grafana accessible.",
	},
	{
		Name:             "netbox",
		DisplayName:      "NetBox",
		DefaultPorts:     []int{8080, 443},
		DockerImages:     []string{"netboxcommunity/netbox"},
		DockerNames:      []string{"netbox"},
		FingerprintPath:  "/api/",
		FingerprintMatch: "dcim",
		CredentialEnvs:   []string{"KITE_NETBOX_TOKEN"},
		SetupHint:        "export KITE_NETBOX_TOKEN=... (from NetBox -> Admin -> API Tokens)",
	},
	{
		Name:             "portainer",
		DisplayName:      "Portainer",
		DefaultPorts:     []int{9443, 9000},
		DockerImages:     []string{"portainer/portainer-ce"},
		FingerprintPath:  "/api/status",
		FingerprintMatch: "Version",
		SetupHint:        "Detected -- Portainer manages Docker (kite uses Docker socket directly).",
	},
	{
		Name:             "otel_collector",
		DisplayName:      "OpenTelemetry Collector",
		DefaultPorts:     []int{4317, 4318},
		DockerImages:     []string{"otel/opentelemetry-collector"},
		DockerNames:      []string{"otelcol", "otel-collector"},
		FingerprintPath:  "/v1/health",
		FingerprintMatch: "",
		SetupHint:        "Ready -- OTel Collector for streaming mode.",
	},
	{
		Name:         "postgres",
		DisplayName:  "PostgreSQL",
		DefaultPorts: []int{5432},
		DockerImages: []string{"postgres"},
		DockerNames:  []string{"postgres", "postgresql"},
		CredentialEnvs: []string{
			"KITE_POSTGRES_DSN",
		},
		SetupHint: "export KITE_POSTGRES_DSN=postgres://user:pass@localhost:5432/kite", //#nosec G101 -- example DSN in setup hint, not actual credentials
	},
}

// allPorts returns a deduplicated slice of all default ports from the given
// service signatures.
func allPorts(services []ServiceSignature) []int {
	seen := make(map[int]struct{})
	var ports []int
	for _, s := range services {
		for _, p := range s.DefaultPorts {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				ports = append(ports, p)
			}
		}
	}
	return ports
}

// servicesByPort builds a lookup from port number to matching service
// signatures.  A port may map to more than one service (e.g. 3000 is used by
// both Grafana and Coolify).
func servicesByPort(services []ServiceSignature) map[int][]ServiceSignature {
	m := make(map[int][]ServiceSignature)
	for _, s := range services {
		for _, p := range s.DefaultPorts {
			m[p] = append(m[p], s)
		}
	}
	return m
}
