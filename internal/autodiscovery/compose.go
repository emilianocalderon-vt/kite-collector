package autodiscovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// probeDockerComposeLabels queries the Docker API for running containers and
// extracts Docker Compose metadata (project, service name) to enrich
// discovery results.  A container is matched against known services by the
// com.docker.compose.service label.
func probeDockerComposeLabels(ctx context.Context, socketPath string, services []ServiceSignature) []DiscoveredService {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(dctx, "unix", socketPath)
			},
		},
	}

	url := fmt.Sprintf("http://localhost/%s/containers/json", dockerAPIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //#nosec G107 -- localhost Docker API
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.Debug("autodiscovery: compose label probe failed", "error", err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var containers []composeContainer
	if err = json.Unmarshal(body, &containers); err != nil {
		return nil
	}

	var results []DiscoveredService

	for _, c := range containers {
		svcLabel := c.Labels["com.docker.compose.service"]
		if svcLabel == "" {
			continue
		}
		project := c.Labels["com.docker.compose.project"]

		for _, sig := range services {
			if !matchComposeService(svcLabel, sig) {
				continue
			}

			endpoint := composeEndpoint(c, sig)
			status, missing := determineStatus(sig)

			hint := sig.SetupHint
			if project != "" {
				hint = fmt.Sprintf("[compose:%s] %s", project, hint)
			}

			results = append(results, DiscoveredService{
				Name:        sig.Name,
				DisplayName: sig.DisplayName,
				Endpoint:    endpoint,
				Method:      "docker_compose",
				Status:      status,
				SetupHint:   hint,
				Credentials: missing,
			})
			break
		}
	}

	return results
}

type composeContainer struct {
	Labels map[string]string   `json:"Labels"`
	ID     string              `json:"Id"`
	Image  string              `json:"Image"`
	Names  []string            `json:"Names"`
	Ports  []dockerPortMapping `json:"Ports"`
}

// matchComposeService checks if the Docker Compose service label matches a
// known service by name or by Docker image/name patterns.
func matchComposeService(svcLabel string, sig ServiceSignature) bool {
	lower := strings.ToLower(svcLabel)
	if lower == sig.Name {
		return true
	}
	for _, name := range sig.DockerNames {
		if strings.Contains(lower, strings.ToLower(name)) {
			return true
		}
	}
	return false
}

func composeEndpoint(c composeContainer, sig ServiceSignature) string {
	// Prefer host-mapped port.
	for _, p := range c.Ports {
		if p.PublicPort <= 0 {
			continue
		}
		for _, dp := range sig.DefaultPorts {
			if p.PrivatePort == dp {
				host := "127.0.0.1"
				if p.IP != "" && p.IP != "0.0.0.0" {
					host = p.IP
				}
				return buildEndpoint(host, p.PublicPort, sig.TLS)
			}
		}
	}

	// Fall back to container name.
	name := ""
	if len(c.Names) > 0 {
		name = strings.TrimPrefix(c.Names[0], "/")
	}
	if name != "" && len(sig.DefaultPorts) > 0 {
		return buildEndpoint(name, sig.DefaultPorts[0], sig.TLS)
	}
	return name
}
