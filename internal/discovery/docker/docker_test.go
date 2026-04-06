package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// -------------------------------------------------------------------------
// Mock Docker API server
// -------------------------------------------------------------------------

func newMockDockerAPI(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/v1.43/containers/json", func(w http.ResponseWriter, _ *http.Request) {
		containers := []containerSummary{
			{
				ID:      "abc123def456789012345678",
				Names:   []string{"/nginx-web"},
				Image:   "nginx:1.25",
				ImageID: "sha256:deadbeef",
				State:   "running",
				Created: 1700000000,
				Ports: []portMapping{
					{PrivatePort: 80, PublicPort: 8080, Type: "tcp"},
				},
				Labels: map[string]string{
					"com.docker.compose.project": "myapp",
				},
			},
			{
				ID:      "def789abc123456789012345",
				Names:   []string{"/redis-cache"},
				Image:   "redis:7",
				ImageID: "sha256:cafebabe",
				State:   "running",
				Created: 1700000100,
				Labels:  map[string]string{},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(containers)
	})

	mux.HandleFunc("/v1.43/containers/abc123def456789012345678/json",
		func(w http.ResponseWriter, _ *http.Request) {
			detail := containerDetail{}
			detail.HostConfig.Privileged = true
			detail.HostConfig.NetworkMode = "host"
			detail.HostConfig.PidMode = "host"
			detail.HostConfig.RestartPolicy.Name = "always"
			detail.HostConfig.Binds = []string{"/data:/var/lib/data:rw"}
			detail.Config.User = ""
			detail.Config.Healthcheck = &struct {
				Test []string `json:"Test"`
			}{
				Test: []string{"CMD", "curl", "-f", "http://localhost/"},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(detail)
		})

	mux.HandleFunc("/v1.43/containers/def789abc123456789012345/json",
		func(w http.ResponseWriter, _ *http.Request) {
			detail := containerDetail{}
			detail.HostConfig.Privileged = false
			detail.HostConfig.NetworkMode = "bridge"
			detail.HostConfig.RestartPolicy.Name = "no"
			detail.Config.User = "appuser"
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(detail)
		})

	mux.HandleFunc("/v1.43/images/json", func(w http.ResponseWriter, _ *http.Request) {
		images := []imageSummary{
			{ID: "sha256:deadbeef", RepoTags: []string{"nginx:1.25"}, Size: 150_000_000, Created: 1700000000},
			{ID: "sha256:cafebabe", RepoTags: []string{"redis:7"}, Size: 120_000_000, Created: 1700000100},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(images)
	})

	return httptest.NewServer(mux)
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

func TestDocker_Name(t *testing.T) {
	d := New()
	assert.Equal(t, "docker", d.Name())
}

func TestDocker_Discover_Success(t *testing.T) {
	srv := newMockDockerAPI(t)
	defer srv.Close()

	d := New()
	cfg := map[string]any{"host": srv.URL}

	assets, err := d.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Len(t, assets, 2)

	// Verify first container.
	nginx := assets[0]
	assert.Equal(t, "nginx-web", nginx.Hostname)
	assert.Equal(t, model.AssetTypeContainer, nginx.AssetType)
	assert.Equal(t, "linux", nginx.OSFamily)
	assert.Equal(t, "nginx:1.25", nginx.OSVersion)
	assert.Equal(t, "docker", nginx.DiscoverySource)
	assert.Equal(t, model.AuthorizationUnknown, nginx.IsAuthorized)

	// Verify tags contain security metadata.
	var tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(nginx.Tags), &tags))
	assert.Equal(t, true, tags["privileged"])
	assert.Equal(t, "host", tags["network_mode"])
	assert.Equal(t, "host", tags["pid_mode"])
	assert.Equal(t, "always", tags["restart_policy"])
	assert.Equal(t, true, tags["healthcheck"])
	assert.Equal(t, "myapp", tags["compose_project"])
	assert.Equal(t, "80/tcp->8080", tags["ports"])

	// Verify second container (non-privileged).
	redis := assets[1]
	assert.Equal(t, "redis-cache", redis.Hostname)

	var redisTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(redis.Tags), &redisTags))
	assert.Equal(t, false, redisTags["privileged"])
	assert.Equal(t, "bridge", redisTags["network_mode"])
	assert.Equal(t, "appuser", redisTags["user"])
}

func TestDocker_Discover_UnreachableHost(t *testing.T) {
	d := New()
	cfg := map[string]any{"host": "unix:///tmp/nonexistent-kite-test.sock"}
	_, err := d.Discover(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "docker: list containers")
}

func TestDocker_Discover_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	d := New()
	cfg := map[string]any{"host": srv.URL}

	_, err := d.Discover(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list containers")
}

func TestContainerToAsset_UUIDv7(t *testing.T) {
	srv := newMockDockerAPI(t)
	defer srv.Close()

	d := New()
	cfg := map[string]any{"host": srv.URL}

	assets, err := d.Discover(context.Background(), cfg)
	require.NoError(t, err)

	for _, a := range assets {
		assert.NotEmpty(t, a.ID, "asset must have a UUID")
	}
}

func TestFormatPorts(t *testing.T) {
	tests := []struct {
		name   string
		expect string
		ports  []portMapping
	}{
		{"empty", "", nil},
		{"public", "80/tcp->8080", []portMapping{{Type: "tcp", PrivatePort: 80, PublicPort: 8080}}},
		{"private_only", "6379/tcp", []portMapping{{Type: "tcp", PrivatePort: 6379}}},
		{"multiple", "80/tcp->8080, 443/tcp->8443", []portMapping{
			{Type: "tcp", PrivatePort: 80, PublicPort: 8080},
			{Type: "tcp", PrivatePort: 443, PublicPort: 8443},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, formatPorts(tt.ports))
		})
	}
}

func TestDetectSocket_NoSocket(t *testing.T) {
	// In a test environment, Docker/Podman sockets likely don't exist.
	// Just verify the function doesn't panic.
	_ = detectSocket()
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "abc", truncate("abcdef", 3))
	assert.Equal(t, "ab", truncate("ab", 5))
	assert.Equal(t, "", truncate("", 3))
}
