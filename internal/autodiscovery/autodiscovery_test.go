package autodiscovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Registry tests
// ---------------------------------------------------------------------------

func TestKnownServicesNotEmpty(t *testing.T) {
	assert.GreaterOrEqual(t, len(KnownServices), 12, "registry should contain at least 12 services")
}

func TestAllPorts(t *testing.T) {
	ports := allPorts(KnownServices)
	assert.NotEmpty(t, ports)

	// Verify deduplication.
	seen := make(map[int]bool)
	for _, p := range ports {
		assert.False(t, seen[p], "port %d appears twice", p)
		seen[p] = true
	}
}

func TestServicesByPort(t *testing.T) {
	m := servicesByPort(KnownServices)
	// Port 3000 is used by both Grafana and Coolify.
	sigs, ok := m[3000]
	assert.True(t, ok, "port 3000 should be in the map")
	assert.GreaterOrEqual(t, len(sigs), 2, "port 3000 should have at least 2 services")
}

// ---------------------------------------------------------------------------
// Gateway parsing tests
// ---------------------------------------------------------------------------

func TestParseGateway(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name: "standard default route",
			input: `Iface	Destination	Gateway	Flags	RefCnt	Use	Metric	Mask	MTU	Window	IRTT
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
eth0	0001A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
`,
			expected: "192.168.1.1",
		},
		{
			name: "no default route",
			input: `Iface	Destination	Gateway	Flags	RefCnt	Use	Metric	Mask	MTU	Window	IRTT
eth0	0001A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
`,
			expected: "",
		},
		{
			name:     "empty input",
			input:    "",
			expected: "",
		},
		{
			name: "gateway 10.0.0.1",
			input: `Iface	Destination	Gateway	Flags	RefCnt	Use	Metric	Mask	MTU	Window	IRTT
wlan0	00000000	0100000A	0003	0	0	600	00000000	0	0	0
`,
			expected: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseGateway([]byte(tt.input))
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHexToIP(t *testing.T) {
	tests := []struct {
		hex      string
		expected string
	}{
		{"0101A8C0", "192.168.1.1"},
		{"0100000A", "10.0.0.1"},
		{"0100007F", "127.0.0.1"},
		{"FEFEA8C0", "192.168.254.254"},
	}

	for _, tt := range tests {
		t.Run(tt.hex, func(t *testing.T) {
			assert.Equal(t, tt.expected, hexToIP(tt.hex))
		})
	}
}

// ---------------------------------------------------------------------------
// Socket probe tests
// ---------------------------------------------------------------------------

func TestProbeSocket_Exists(t *testing.T) {
	// Create a real Unix socket listener in a temp directory.
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	lc := net.ListenConfig{}
	l, err := lc.Listen(context.Background(), "unix", sockPath)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	assert.True(t, probeSocket(sockPath))
}

func TestProbeSocket_NotExists(t *testing.T) {
	assert.False(t, probeSocket("/tmp/nonexistent-kite-test.sock"))
}

func TestProbeSocket_RegularFile(t *testing.T) {
	// A regular file is not a socket.
	f, err := os.CreateTemp("", "kite-test-*")
	require.NoError(t, err)
	_ = f.Close()
	defer func() { _ = os.Remove(f.Name()) }()

	assert.False(t, probeSocket(f.Name()))
}

func TestExpandSocketPath(t *testing.T) {
	assert.Equal(t, "/run/user/1000/podman/podman.sock", expandSocketPath("/run/user/%d/podman/podman.sock", 1000))
	assert.Equal(t, "/var/run/docker.sock", expandSocketPath("/var/run/docker.sock", 1000))
}

func TestProbeAllSockets(t *testing.T) {
	// Create a socket at a temp path.
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "docker.sock")

	lc := net.ListenConfig{}
	l, err := lc.Listen(context.Background(), "unix", sockPath)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	services := []ServiceSignature{
		{
			Name:        "test_docker",
			DisplayName: "Test Docker",
			SocketPaths: []string{sockPath},
			SetupHint:   "Ready.",
		},
	}

	results := probeAllSockets(services)
	require.Len(t, results, 1)
	assert.Equal(t, "test_docker", results[0].Name)
	assert.Equal(t, sockPath, results[0].Endpoint)
	assert.Equal(t, "socket", results[0].Method)
	assert.Equal(t, "ready", results[0].Status)
}

// ---------------------------------------------------------------------------
// Port probe tests
// ---------------------------------------------------------------------------

func TestProbePorts(t *testing.T) {
	// Start a TCP listener on a random port.
	lc := net.ListenConfig{}
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	port := l.Addr().(*net.TCPAddr).Port

	ctx := context.Background()
	open := probePorts(ctx, []string{"127.0.0.1"}, []int{port, port + 1}, 1000)

	// The listener port should be found; port+1 should not.
	found := false
	for _, op := range open {
		if op.Port == port {
			found = true
		}
		assert.NotEqual(t, port+1, op.Port, "closed port should not appear")
	}
	assert.True(t, found, "listener port should be detected as open")
}

func TestProbePorts_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	open := probePorts(ctx, []string{"127.0.0.1"}, []int{80, 443}, 500)
	assert.Empty(t, open)
}

// ---------------------------------------------------------------------------
// Fingerprint tests
// ---------------------------------------------------------------------------

func TestFingerprint_BodyMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"title": "Wazuh API REST", "version": "4.9.0"}`)
	}))
	defer srv.Close()

	ok, _ := fingerprint(context.Background(), srv.URL, "/", "Wazuh API REST", 3*time.Second)
	assert.True(t, ok)
}

func TestFingerprint_HeaderMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Prometheus/2.50")
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	ok, _ := fingerprint(context.Background(), srv.URL, "/", "Prometheus", 3*time.Second)
	assert.True(t, ok)
}

func TestFingerprint_NoMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "some random service")
	}))
	defer srv.Close()

	ok, _ := fingerprint(context.Background(), srv.URL, "/", "Wazuh", 3*time.Second)
	assert.False(t, ok)
}

func TestFingerprint_ConnectionRefused(t *testing.T) {
	ok, _ := fingerprint(context.Background(), "http://127.0.0.1:1", "/", "anything", 500*time.Millisecond)
	assert.False(t, ok)
}

func TestFingerprintOpenPorts(t *testing.T) {
	// Start a mock ClickHouse ping endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			_, _ = fmt.Fprint(w, "Ok.\n")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// Extract port from the test server.
	parts := strings.Split(srv.URL, ":")
	port, _ := strconv.Atoi(parts[len(parts)-1])

	services := []ServiceSignature{
		{
			Name:             "clickhouse",
			DisplayName:      "ClickHouse",
			DefaultPorts:     []int{port},
			FingerprintPath:  "/ping",
			FingerprintMatch: "Ok",
			SetupHint:        "Ready.",
		},
	}

	open := []openPort{{Host: "127.0.0.1", Port: port}}
	results := fingerprintOpenPorts(context.Background(), open, services, 3000)

	require.Len(t, results, 1)
	assert.Equal(t, "clickhouse", results[0].Name)
	assert.Equal(t, "port_scan", results[0].Method)
	assert.Equal(t, "ready", results[0].Status)
}

// ---------------------------------------------------------------------------
// Docker container probe tests
// ---------------------------------------------------------------------------

func TestMatchContainer(t *testing.T) {
	sig := ServiceSignature{
		DockerImages: []string{"wazuh/wazuh-manager"},
		DockerNames:  []string{"wazuh-manager"},
	}

	tests := []struct {
		name      string
		container dockerContainer
		want      bool
	}{
		{
			name:      "match by image",
			container: dockerContainer{Image: "wazuh/wazuh-manager:4.9.0"},
			want:      true,
		},
		{
			name:      "match by name",
			container: dockerContainer{Names: []string{"/wazuh-manager"}},
			want:      true,
		},
		{
			name:      "no match",
			container: dockerContainer{Image: "nginx:latest", Names: []string{"/web"}},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchContainer(tt.container, sig))
		})
	}
}

func TestContainerEndpoint_HostPort(t *testing.T) {
	c := dockerContainer{
		Names: []string{"/wazuh-manager"},
		Ports: []dockerPortMapping{
			{PrivatePort: 55000, PublicPort: 55000, IP: "0.0.0.0"},
		},
	}
	sig := ServiceSignature{
		DefaultPorts: []int{55000},
		TLS:          true,
	}

	endpoint := containerEndpoint(c, sig)
	assert.Equal(t, "https://127.0.0.1:55000", endpoint)
}

func TestContainerEndpoint_NoHostPort(t *testing.T) {
	c := dockerContainer{
		Names: []string{"/wazuh-manager"},
		Ports: []dockerPortMapping{
			{PrivatePort: 55000, PublicPort: 0},
		},
	}
	sig := ServiceSignature{
		DefaultPorts: []int{55000},
		TLS:          true,
	}

	endpoint := containerEndpoint(c, sig)
	// Should fall back to container name.
	assert.Equal(t, "https://wazuh-manager:55000", endpoint)
}

func TestProbeDockerContainers_MockAPI(t *testing.T) {
	// Create a mock Docker API server over Unix socket.
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "docker.sock")

	lc := net.ListenConfig{}
	l, err := lc.Listen(context.Background(), "unix", sockPath)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	containers := []dockerContainer{
		{
			ID:    "abc123",
			Image: "clickhouse/clickhouse-server:24.1",
			Names: []string{"/clickhouse"},
			State: "running",
			Ports: []dockerPortMapping{
				{PrivatePort: 8123, PublicPort: 8123, IP: "0.0.0.0"},
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(containers)
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close() }()

	services := []ServiceSignature{
		{
			Name:         "clickhouse",
			DisplayName:  "ClickHouse",
			DefaultPorts: []int{8123},
			DockerImages: []string{"clickhouse/clickhouse-server"},
			DockerNames:  []string{"clickhouse"},
			SetupHint:    "Ready.",
		},
	}

	results := probeDockerContainers(context.Background(), sockPath, services)
	require.Len(t, results, 1)
	assert.Equal(t, "clickhouse", results[0].Name)
	assert.Equal(t, "docker_container", results[0].Method)
	assert.Equal(t, "http://127.0.0.1:8123", results[0].Endpoint)
}

// ---------------------------------------------------------------------------
// Environment variable probe tests
// ---------------------------------------------------------------------------

func TestProbeEnvVars_Found(t *testing.T) {
	t.Setenv("KITE_TEST_TOKEN", "secret123")

	services := []ServiceSignature{
		{
			Name:           "test_svc",
			DisplayName:    "Test Service",
			CredentialEnvs: []string{"KITE_TEST_TOKEN"},
			SetupHint:      "Ready.",
		},
	}

	results := probeEnvVars(services)
	require.Len(t, results, 1)
	assert.Equal(t, "test_svc", results[0].Name)
	assert.Equal(t, "ready", results[0].Status)
	assert.Equal(t, "env_var", results[0].Method)
}

func TestProbeEnvVars_PartialCredentials(t *testing.T) {
	t.Setenv("KITE_TEST_USER", "admin")
	// KITE_TEST_PASS is not set.

	services := []ServiceSignature{
		{
			Name:           "test_svc",
			DisplayName:    "Test Service",
			CredentialEnvs: []string{"KITE_TEST_USER", "KITE_TEST_PASS"},
			SetupHint:      "Set the password.",
		},
	}

	results := probeEnvVars(services)
	require.Len(t, results, 1)
	assert.Equal(t, "needs_credentials", results[0].Status)
	assert.Contains(t, results[0].Credentials, "KITE_TEST_PASS")
}

func TestProbeEnvVars_NothingSet(t *testing.T) {
	services := []ServiceSignature{
		{
			Name:           "test_svc",
			DisplayName:    "Test Service",
			CredentialEnvs: []string{"KITE_TEST_NOPE_1", "KITE_TEST_NOPE_2"},
		},
	}

	results := probeEnvVars(services)
	assert.Empty(t, results)
}

func TestProbeEnvVars_EndpointEnvVar(t *testing.T) {
	t.Setenv("KITE_UNIFI_ENDPOINT", "https://192.168.1.1:8443")

	services := []ServiceSignature{
		{
			Name:           "unifi",
			DisplayName:    "UniFi Controller",
			EnvVars:        []string{"KITE_UNIFI_ENDPOINT"},
			CredentialEnvs: []string{"KITE_UNIFI_API_KEY_NOTSET"},
			SetupHint:      "Set API key.",
		},
	}

	results := probeEnvVars(services)
	require.Len(t, results, 1)
	assert.Equal(t, "https://192.168.1.1:8443", results[0].Endpoint)
	assert.Equal(t, "needs_credentials", results[0].Status)
}

// ---------------------------------------------------------------------------
// Deduplication tests
// ---------------------------------------------------------------------------

func TestDeduplicateResults(t *testing.T) {
	results := []DiscoveredService{
		{Name: "clickhouse", Method: "docker_container", Status: "ready", Endpoint: "http://clickhouse:8123"},
		{Name: "clickhouse", Method: "port_scan", Status: "ready", Endpoint: "http://127.0.0.1:8123"},
		{Name: "wazuh", Method: "docker_container", Status: "needs_credentials", Endpoint: "https://wazuh:55000"},
	}

	deduped := deduplicateResults(results)
	assert.Len(t, deduped, 2)

	// clickhouse should prefer port_scan (higher method priority at same status).
	for _, r := range deduped {
		if r.Name == "clickhouse" {
			assert.Equal(t, "port_scan", r.Method)
			assert.Equal(t, "http://127.0.0.1:8123", r.Endpoint)
		}
	}
}

func TestDeduplicateResults_StatusWins(t *testing.T) {
	results := []DiscoveredService{
		{Name: "wazuh", Method: "docker_container", Status: "needs_credentials"},
		{Name: "wazuh", Method: "env_var", Status: "ready"},
	}

	deduped := deduplicateResults(results)
	require.Len(t, deduped, 1)
	assert.Equal(t, "ready", deduped[0].Status)
	assert.Equal(t, "env_var", deduped[0].Method)
}

// ---------------------------------------------------------------------------
// Run orchestrator test
// ---------------------------------------------------------------------------

func TestRun_WithMockServices(t *testing.T) {
	// Start a mock HTTP server that responds to /ping with "Ok.".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			_, _ = fmt.Fprint(w, "Ok.\n")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	parts := strings.Split(srv.URL, ":")
	port, _ := strconv.Atoi(parts[len(parts)-1])

	services := []ServiceSignature{
		{
			Name:             "mock_ch",
			DisplayName:      "Mock ClickHouse",
			DefaultPorts:     []int{port},
			FingerprintPath:  "/ping",
			FingerprintMatch: "Ok",
			SetupHint:        "Ready.",
		},
	}

	results := Run(context.Background(), Options{
		Targets:  []string{"127.0.0.1"},
		Services: services,
	})

	require.Len(t, results, 1)
	assert.Equal(t, "mock_ch", results[0].Name)
	assert.Equal(t, "ready", results[0].Status)
	assert.Equal(t, "port_scan", results[0].Method)
}

// ---------------------------------------------------------------------------
// DetermineStatus tests
// ---------------------------------------------------------------------------

func TestDetermineStatus_NoCredentials(t *testing.T) {
	sig := ServiceSignature{Name: "docker"}
	status, missing := determineStatus(sig)
	assert.Equal(t, "ready", status)
	assert.Nil(t, missing)
}

func TestDetermineStatus_AllCredentialsSet(t *testing.T) {
	t.Setenv("KITE_TEST_A", "val")
	t.Setenv("KITE_TEST_B", "val")

	sig := ServiceSignature{
		Name:           "test",
		CredentialEnvs: []string{"KITE_TEST_A", "KITE_TEST_B"},
	}
	status, missing := determineStatus(sig)
	assert.Equal(t, "ready", status)
	assert.Nil(t, missing)
}

func TestDetermineStatus_MissingCredentials(t *testing.T) {
	sig := ServiceSignature{
		Name:           "test",
		CredentialEnvs: []string{"KITE_TEST_MISSING_1", "KITE_TEST_MISSING_2"},
	}
	status, missing := determineStatus(sig)
	assert.Equal(t, "needs_credentials", status)
	assert.Len(t, missing, 2)
}

// ---------------------------------------------------------------------------
// BuildEndpoint test
// ---------------------------------------------------------------------------

func TestBuildEndpoint(t *testing.T) {
	assert.Equal(t, "http://127.0.0.1:8123", buildEndpoint("127.0.0.1", 8123, false))
	assert.Equal(t, "https://192.168.1.1:8006", buildEndpoint("192.168.1.1", 8006, true))
}

// ---------------------------------------------------------------------------
// Docker Compose label probe tests
// ---------------------------------------------------------------------------

func TestMatchComposeService(t *testing.T) {
	sig := ServiceSignature{
		Name:        "clickhouse",
		DockerNames: []string{"clickhouse"},
	}

	assert.True(t, matchComposeService("clickhouse", sig))
	assert.True(t, matchComposeService("Clickhouse", sig))
	assert.False(t, matchComposeService("nginx", sig))
}

func TestProbeDockerComposeLabels_MockAPI(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "docker.sock")

	lc := net.ListenConfig{}
	l, err := lc.Listen(context.Background(), "unix", sockPath)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	containers := []composeContainer{
		{
			ID:    "def456",
			Image: "prom/prometheus:v2.50",
			Names: []string{"/prometheus"},
			Labels: map[string]string{
				"com.docker.compose.service": "prometheus",
				"com.docker.compose.project": "monitoring",
			},
			Ports: []dockerPortMapping{
				{PrivatePort: 9090, PublicPort: 9090, IP: "0.0.0.0"},
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(containers)
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close() }()

	services := []ServiceSignature{
		{
			Name:         "prometheus",
			DisplayName:  "Prometheus",
			DefaultPorts: []int{9090},
			DockerNames:  []string{"prometheus"},
			SetupHint:    "Ready.",
		},
	}

	results := probeDockerComposeLabels(context.Background(), sockPath, services)
	require.Len(t, results, 1)
	assert.Equal(t, "prometheus", results[0].Name)
	assert.Equal(t, "docker_compose", results[0].Method)
	assert.Contains(t, results[0].SetupHint, "compose:monitoring")
}

// ---------------------------------------------------------------------------
// Kubernetes probe tests
// ---------------------------------------------------------------------------

func TestMatchK8sService(t *testing.T) {
	sig := ServiceSignature{
		Name:        "prometheus",
		DockerNames: []string{"prometheus"},
	}

	assert.True(t, matchK8sService("prometheus", sig))
	assert.True(t, matchK8sService("kube-prometheus", sig))
	assert.False(t, matchK8sService("nginx", sig))
}

func TestK8sEndpoint(t *testing.T) {
	svc := k8sService{
		Metadata: k8sMetadata{Name: "clickhouse"},
		Spec: k8sServiceSpec{
			ClusterIP: "10.96.0.15",
			Ports:     []k8sPortDef{{Port: 8123}},
		},
	}
	sig := ServiceSignature{
		DefaultPorts: []int{8123},
	}

	assert.Equal(t, "http://10.96.0.15:8123", k8sEndpoint(svc, sig))
}

func TestK8sEndpoint_NoClusterIP(t *testing.T) {
	svc := k8sService{
		Metadata: k8sMetadata{Name: "prometheus"},
		Spec: k8sServiceSpec{
			ClusterIP: "None",
			Ports:     []k8sPortDef{{Port: 9090}},
		},
	}
	sig := ServiceSignature{
		DefaultPorts: []int{9090},
	}

	assert.Equal(t, "http://prometheus:9090", k8sEndpoint(svc, sig))
}

func TestProbeK8s_NotInCluster(t *testing.T) {
	// Outside of Kubernetes, the token file doesn't exist.
	results := probeK8s(context.Background(), KnownServices)
	assert.Empty(t, results)
}

// ---------------------------------------------------------------------------
// DNS probe tests
// ---------------------------------------------------------------------------

func TestProbeDNS_NoResolution(t *testing.T) {
	// In a normal test environment, .local hostnames won't resolve.
	// The probe should return empty without errors.
	results := probeDNS(context.Background(), KnownServices, 500)
	assert.Empty(t, results)
}
