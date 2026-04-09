// Package docker implements a discovery.Source that enumerates containers and
// images from a Docker or Podman Engine API.  Communication uses raw HTTP over
// a Unix socket (or TCP) — no vendor SDK dependency.
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safenet"
)

const (
	apiVersion    = "v1.43"
	clientTimeout = 30 * time.Second
)

// Docker implements discovery.Source for the Docker/Podman Engine API.
type Docker struct{}

// New returns a new Docker discovery source.
func New() *Docker { return &Docker{} }

// Name returns the stable identifier for this source.
func (d *Docker) Name() string { return "docker" }

// Discover enumerates containers via the Docker/Podman Engine API and returns
// them as assets.  The host is resolved from (in order): cfg["host"],
// KITE_DOCKER_HOST env, or auto-detected socket paths.
func (d *Docker) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	host := toString(cfg["host"])
	if host == "" {
		host = os.Getenv("KITE_DOCKER_HOST")
	}
	if host == "" {
		host = detectSocket()
	}
	if host == "" {
		return nil, fmt.Errorf("docker: no socket found; set KITE_DOCKER_HOST or ensure Docker/Podman is running")
	}

	slog.Info("docker: starting discovery", "host", host) //#nosec G706 -- structured slog key-value, not interpolated

	client := newClient(host)

	containers, err := client.listContainers(ctx)
	if err != nil {
		return nil, fmt.Errorf("docker: list containers: %w", err)
	}

	now := time.Now().UTC()
	assets := make([]model.Asset, 0, len(containers))

	for _, c := range containers {
		detail, inspErr := client.inspectContainer(ctx, c.ID)
		if inspErr != nil {
			slog.Warn("docker: inspect failed", "container", c.ID[:12], "error", inspErr)
		}
		assets = append(assets, containerToAsset(c, detail, now))
	}

	images, imgErr := client.listImages(ctx)
	if imgErr != nil {
		slog.Warn("docker: list images failed", "error", imgErr)
	} else {
		slog.Info("docker: images discovered", "count", len(images)) //#nosec G706 -- structured slog
	}

	slog.Info("docker: discovery complete", "containers", len(assets)) //#nosec G706 -- structured slog
	return assets, nil
}

// -------------------------------------------------------------------------
// HTTP client
// -------------------------------------------------------------------------

type dockerClient struct {
	http *http.Client
	base string
}

func newClient(host string) *dockerClient {
	var transport http.RoundTripper

	if strings.HasPrefix(host, "unix://") {
		sockPath := strings.TrimPrefix(host, "unix://")
		transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: clientTimeout}
				return d.DialContext(ctx, "unix", sockPath) //#nosec G704 -- socket path from user config
			},
		}
		host = "http://localhost"
	} else {
		if !strings.HasPrefix(host, "http") {
			host = "http://" + host
		}
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}

	return &dockerClient{
		base: strings.TrimRight(host, "/"),
		http: &http.Client{Transport: transport, Timeout: clientTimeout},
	}
}

func (c *dockerClient) get(ctx context.Context, path string) ([]byte, error) {
	url := fmt.Sprintf("%s/%s%s", c.base, apiVersion, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //#nosec G704 -- URL from user-configured Docker host
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req) //#nosec G704 -- intentional request to user-configured endpoint
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	return body, nil
}

// -------------------------------------------------------------------------
// API types
// -------------------------------------------------------------------------

type containerSummary struct {
	Labels          map[string]string `json:"Labels"`
	NetworkSettings struct {
		Networks map[string]struct{} `json:"Networks"`
	} `json:"NetworkSettings"`
	ID      string        `json:"Id"`
	Image   string        `json:"Image"`
	ImageID string        `json:"ImageID"`
	State   string        `json:"State"`
	Names   []string      `json:"Names"`
	Ports   []portMapping `json:"Ports"`
	Created int64         `json:"Created"`
}

type portMapping struct {
	Type        string `json:"Type"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
}

type containerDetail struct {
	Config struct {
		Healthcheck *struct {
			Test []string `json:"Test"`
		} `json:"Healthcheck"`
		User string `json:"User"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode   string `json:"NetworkMode"`
		PidMode       string `json:"PidMode"`
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
		Binds      []string `json:"Binds"`
		Privileged bool     `json:"Privileged"`
	} `json:"HostConfig"`
}

type imageSummary struct {
	ID       string   `json:"Id"`
	RepoTags []string `json:"RepoTags"`
	Size     int64    `json:"Size"`
	Created  int64    `json:"Created"`
}

// -------------------------------------------------------------------------
// API calls
// -------------------------------------------------------------------------

func (c *dockerClient) listContainers(ctx context.Context) ([]containerSummary, error) {
	body, err := c.get(ctx, "/containers/json?all=true")
	if err != nil {
		return nil, err
	}
	var containers []containerSummary
	if err = json.Unmarshal(body, &containers); err != nil {
		return nil, fmt.Errorf("parse containers: %w", err)
	}
	return containers, nil
}

func (c *dockerClient) inspectContainer(ctx context.Context, id string) (*containerDetail, error) {
	safeID, err := safenet.SanitizePathSegment(id)
	if err != nil {
		return nil, fmt.Errorf("invalid container ID: %w", err)
	}
	body, err := c.get(ctx, "/containers/"+safeID+"/json")
	if err != nil {
		return nil, err
	}
	var detail containerDetail
	if err = json.Unmarshal(body, &detail); err != nil {
		return nil, fmt.Errorf("parse inspect: %w", err)
	}
	return &detail, nil
}

func (c *dockerClient) listImages(ctx context.Context) ([]imageSummary, error) {
	body, err := c.get(ctx, "/images/json")
	if err != nil {
		return nil, err
	}
	var images []imageSummary
	if err = json.Unmarshal(body, &images); err != nil {
		return nil, fmt.Errorf("parse images: %w", err)
	}
	return images, nil
}

// -------------------------------------------------------------------------
// Asset mapping
// -------------------------------------------------------------------------

func containerToAsset(c containerSummary, detail *containerDetail, now time.Time) model.Asset {
	name := ""
	if len(c.Names) > 0 {
		name = strings.TrimPrefix(c.Names[0], "/")
	}

	tags := buildContainerTags(c, detail)
	tagsJSON, _ := json.Marshal(tags)

	created := time.Unix(c.Created, 0).UTC()

	return model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        name,
		AssetType:       model.AssetTypeContainer,
		OSFamily:        "linux",
		OSVersion:       c.Image,
		DiscoverySource: "docker",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            string(tagsJSON),
		FirstSeenAt:     created,
		LastSeenAt:      now,
	}
}

func buildContainerTags(c containerSummary, detail *containerDetail) map[string]any {
	tags := map[string]any{
		"container_id": truncate(c.ID, 12),
		"image":        c.Image,
		"image_id":     c.ImageID,
		"state":        c.State,
		"ports":        formatPorts(c.Ports),
		"networks":     networkNames(c),
	}

	if project, ok := c.Labels["com.docker.compose.project"]; ok {
		tags["compose_project"] = project
	}

	if detail != nil {
		tags["privileged"] = detail.HostConfig.Privileged
		tags["network_mode"] = detail.HostConfig.NetworkMode
		tags["pid_mode"] = detail.HostConfig.PidMode
		tags["restart_policy"] = detail.HostConfig.RestartPolicy.Name
		tags["healthcheck"] = detail.Config.Healthcheck != nil
		tags["mounts"] = detail.HostConfig.Binds
		tags["user"] = detail.Config.User
	}

	return tags
}

func formatPorts(ports []portMapping) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		if p.PublicPort > 0 {
			parts = append(parts, fmt.Sprintf("%d/%s->%d", p.PrivatePort, p.Type, p.PublicPort))
		} else {
			parts = append(parts, strconv.Itoa(p.PrivatePort)+"/"+p.Type)
		}
	}
	return strings.Join(parts, ", ")
}

func networkNames(c containerSummary) []string {
	names := make([]string, 0, len(c.NetworkSettings.Networks))
	for name := range c.NetworkSettings.Networks {
		names = append(names, name)
	}
	return names
}

// -------------------------------------------------------------------------
// Socket detection
// -------------------------------------------------------------------------

// detectSocket checks common Docker and Podman socket paths.
// On Windows it checks the Docker Desktop named pipe and TCP endpoint.
func detectSocket() string {
	if runtime.GOOS == "windows" {
		return detectSocketWindows()
	}
	return detectSocketUnix()
}

// detectSocketUnix checks Unix socket paths for Docker and Podman.
func detectSocketUnix() string {
	paths := []string{
		"/var/run/docker.sock",
		"/run/podman/podman.sock",
	}
	// Rootless Podman socket for the current user.
	if uid := os.Getuid(); uid > 0 {
		paths = append(paths, fmt.Sprintf("/run/user/%d/podman/podman.sock", uid))
	}
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.Mode().Type() == os.ModeSocket {
			return "unix://" + p
		}
	}
	return ""
}

// detectSocketWindows probes for Docker Desktop on Windows via named pipe
// or TCP endpoint.
func detectSocketWindows() string {
	// Check Docker Desktop named pipe.
	pipe := `\\.\pipe\docker_engine`
	if _, err := os.Stat(pipe); err == nil {
		// Named pipe exists — Docker Desktop is running.
		// Use TCP endpoint which Docker Desktop exposes.
		return "tcp://localhost:2375"
	}
	// Try Docker Desktop TCP directly.
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(context.Background(), "tcp", "localhost:2375")
	if err == nil {
		_ = conn.Close()
		return "tcp://localhost:2375"
	}
	return ""
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
