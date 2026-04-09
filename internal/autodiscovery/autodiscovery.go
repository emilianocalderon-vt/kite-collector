package autodiscovery

import (
	"context"
	"log/slog"
	"os"
	"sort"
	"sync"

	"github.com/vulnertrack/kite-collector/internal/safenet"
)

// DiscoveredService represents an infrastructure service found by the
// autodiscovery engine.  Fields are ordered strings-first, slices-second
// to minimise GC pointer bitmap overhead (fieldalignment).
type DiscoveredService struct {
	// Name is the stable service identifier (matches ServiceSignature.Name).
	Name string `json:"name"`
	// DisplayName is a human-readable label.
	DisplayName string `json:"display_name"`
	// Endpoint is the address at which the service was found.
	Endpoint string `json:"endpoint"`
	// Method describes how the service was detected.
	Method string `json:"method"` // "socket", "port_scan", "docker_container", "env_var"
	// Status indicates readiness.
	Status string `json:"status"` // "ready", "needs_credentials", "detected"
	// SetupHint provides human-readable instructions.
	SetupHint string `json:"setup_hint,omitempty"`
	// Version is the service version extracted from the fingerprint
	// response, if available.
	Version string `json:"version,omitempty"`
	// Credentials lists missing environment variable names.
	Credentials []string `json:"credentials,omitempty"`
}

// Options configures a discovery run.
type Options struct {
	// Targets is the list of IP addresses to probe (default: 127.0.0.1 +
	// detected gateway).
	Targets []string
	// Services overrides the default KnownServices registry (for testing).
	Services []ServiceSignature
	// PortTimeout is the TCP connect timeout for port probing.  Zero means
	// use the default (2 seconds).
	PortTimeout int
	// HTTPTimeout is the timeout for HTTP fingerprint requests.  Zero
	// means use the default (3 seconds).
	HTTPTimeout int
}

// Run executes all discovery probes in parallel and returns a merged,
// deduplicated list of discovered services sorted by name.
func Run(ctx context.Context, opts Options) []DiscoveredService {
	services := opts.Services
	if len(services) == 0 {
		services = KnownServices
	}

	targets := opts.Targets
	if len(targets) == 0 {
		targets = []string{"127.0.0.1"}
		if gw := defaultGateway(); gw != "" {
			targets = append(targets, gw)
			slog.Info("autodiscovery: detected default gateway", "gateway", gw)
		}
	}

	var (
		mu      sync.Mutex
		results []DiscoveredService
	)

	collect := func(discovered []DiscoveredService) {
		mu.Lock()
		results = append(results, discovered...)
		mu.Unlock()
	}

	// Socket probe runs synchronously (fast — just stat calls).
	socketResults := probeAllSockets(services)
	collect(socketResults)

	// Determine Docker/Podman socket for container inspection.
	var dockerSocket string
	for _, r := range socketResults {
		if r.Name == "docker" || r.Name == "podman" {
			dockerSocket = r.Endpoint
			break
		}
	}

	// Run remaining probes in parallel.
	var wg sync.WaitGroup

	// Port probe + fingerprinting.
	safenet.SafeGo(&wg, slog.Default(), "autodiscovery-ports", func() {
		ports := allPorts(services)
		if len(ports) == 0 {
			return
		}
		open := probePorts(ctx, targets, ports, opts.PortTimeout)
		discovered := fingerprintOpenPorts(ctx, open, services, opts.HTTPTimeout)
		collect(discovered)
	})

	// Docker container probe.
	if dockerSocket != "" {
		safenet.SafeGo(&wg, slog.Default(), "autodiscovery-docker", func() {
			discovered := probeDockerContainers(ctx, dockerSocket, services)
			collect(discovered)
		})
	}

	// Docker Compose label probe.
	if dockerSocket != "" {
		safenet.SafeGo(&wg, slog.Default(), "autodiscovery-compose", func() {
			discovered := probeDockerComposeLabels(ctx, dockerSocket, services)
			collect(discovered)
		})
	}

	// Environment variable probe.
	safenet.SafeGo(&wg, slog.Default(), "autodiscovery-env", func() {
		discovered := probeEnvVars(services)
		collect(discovered)
	})

	// DNS/mDNS .local probe.
	safenet.SafeGo(&wg, slog.Default(), "autodiscovery-dns", func() {
		discovered := probeDNS(ctx, services, opts.HTTPTimeout)
		collect(discovered)
	})

	// Kubernetes in-cluster probe.
	safenet.SafeGo(&wg, slog.Default(), "autodiscovery-k8s", func() {
		discovered := probeK8s(ctx, services)
		collect(discovered)
	})

	wg.Wait()

	return deduplicateResults(results)
}

// defaultGateway attempts to read the default gateway from /proc/net/route.
// Returns an empty string if the gateway cannot be determined.
func defaultGateway() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	return parseGateway(data)
}

// parseGateway extracts the default gateway IP from /proc/net/route content.
func parseGateway(data []byte) string {
	lines := splitLines(data)
	if len(lines) < 2 {
		return ""
	}
	for _, line := range lines[1:] { // skip header
		fields := splitFields(line)
		if len(fields) < 3 {
			continue
		}
		// Default route has destination 00000000.
		if fields[1] != "00000000" {
			continue
		}
		return hexToIP(fields[2])
	}
	return ""
}

// hexToIP converts a hex-encoded IP from /proc/net/route to dotted notation.
// The format is a 32-bit value in host byte order (little-endian on x86).
func hexToIP(hex string) string {
	if len(hex) != 8 {
		return ""
	}
	var ip [4]byte
	for i := 0; i < 4; i++ {
		b := hexByte(hex[i*2], hex[i*2+1])
		ip[3-i] = b
	}
	return formatIP(ip)
}

func hexByte(hi, lo byte) byte {
	return hexNibble(hi)<<4 | hexNibble(lo)
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}

func formatIP(ip [4]byte) string {
	buf := make([]byte, 0, 15)
	for i, b := range ip {
		if i > 0 {
			buf = append(buf, '.')
		}
		buf = appendUint(buf, b)
	}
	return string(buf)
}

func appendUint(buf []byte, v byte) []byte {
	if v >= 100 {
		buf = append(buf, '0'+v/100)
		v %= 100
		buf = append(buf, '0'+v/10)
		buf = append(buf, '0'+v%10)
		return buf
	}
	if v >= 10 {
		buf = append(buf, '0'+v/10)
		buf = append(buf, '0'+v%10)
		return buf
	}
	return append(buf, '0'+v)
}

func splitLines(data []byte) []string {
	var lines []string
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				lines = append(lines, string(data[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, string(data[start:]))
	}
	return lines
}

func splitFields(line string) []string {
	var fields []string
	start := -1
	for i, c := range line {
		if c == ' ' || c == '\t' {
			if start >= 0 {
				fields = append(fields, line[start:i])
				start = -1
			}
		} else {
			if start < 0 {
				start = i
			}
		}
	}
	if start >= 0 {
		fields = append(fields, line[start:])
	}
	return fields
}

// methodPriority returns a numeric priority for deduplication.  Higher values
// win when two probes find the same service.
func methodPriority(method string) int {
	switch method {
	case "port_scan":
		return 4 // highest — confirmed by HTTP fingerprint
	case "docker_container":
		return 3
	case "socket":
		return 2
	case "env_var":
		return 1
	default:
		return 0
	}
}

// statusPriority returns a numeric priority.  "ready" beats
// "needs_credentials" beats "detected".
func statusPriority(status string) int {
	switch status {
	case "ready":
		return 3
	case "needs_credentials":
		return 2
	case "detected":
		return 1
	default:
		return 0
	}
}

// deduplicateResults merges discovery results, keeping the best entry for
// each service name.  "Best" means highest status priority, then highest
// method priority.
func deduplicateResults(results []DiscoveredService) []DiscoveredService {
	best := make(map[string]DiscoveredService, len(results))
	for _, r := range results {
		existing, ok := best[r.Name]
		if !ok {
			best[r.Name] = r
			continue
		}
		// Prefer higher status, then higher method priority.
		es := statusPriority(existing.Status)
		rs := statusPriority(r.Status)
		if rs > es || (rs == es && methodPriority(r.Method) > methodPriority(existing.Method)) {
			best[r.Name] = r
		}
	}

	out := make([]DiscoveredService, 0, len(best))
	for _, v := range best {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// determineStatus checks credential environment variables and returns the
// appropriate status string.
func determineStatus(sig ServiceSignature) (status string, missing []string) {
	if len(sig.CredentialEnvs) == 0 {
		return "ready", nil
	}
	for _, env := range sig.CredentialEnvs {
		if os.Getenv(env) == "" {
			missing = append(missing, env)
		}
	}
	if len(missing) == 0 {
		return "ready", nil
	}
	return "needs_credentials", missing
}
