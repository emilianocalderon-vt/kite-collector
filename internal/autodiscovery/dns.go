package autodiscovery

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"
)

const dnsLookupTimeout = 2 * time.Second

// Well-known .local hostnames to probe.
var localHostnames = []struct {
	hostname string
	service  string
}{
	{"wazuh-manager.local", "wazuh"},
	{"wazuh.local", "wazuh"},
	{"unifi.local", "unifi"},
	{"proxmox.local", "proxmox"},
	{"clickhouse.local", "clickhouse"},
	{"prometheus.local", "prometheus"},
	{"grafana.local", "grafana"},
	{"netbox.local", "netbox"},
	{"portainer.local", "portainer"},
	{"coolify.local", "coolify"},
}

// probeDNS attempts to resolve well-known .local hostnames using the system
// resolver and, for each that resolves, probes the service's default port and
// fingerprint endpoint.
func probeDNS(ctx context.Context, services []ServiceSignature, httpTimeoutMs int) []DiscoveredService {
	httpTimeout := defaultHTTPTimeout
	if httpTimeoutMs > 0 {
		httpTimeout = time.Duration(httpTimeoutMs) * time.Millisecond
	}

	sigByName := make(map[string]ServiceSignature, len(services))
	for _, s := range services {
		sigByName[s.Name] = s
	}

	resolver := net.DefaultResolver

	var results []DiscoveredService

	for _, entry := range localHostnames {
		sig, ok := sigByName[entry.service]
		if !ok {
			continue
		}

		// Per-hostname timeout to avoid slow lookups blocking the whole probe.
		lookupCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
		addrs, err := resolver.LookupHost(lookupCtx, entry.hostname)
		cancel()

		if err != nil || len(addrs) == 0 {
			continue
		}

		ip := addrs[0]
		slog.Info("autodiscovery: DNS resolved", "hostname", entry.hostname, "ip", ip)

		// Try fingerprinting on each default port.
		for _, port := range sig.DefaultPorts {
			endpoint := buildEndpoint(ip, port, sig.TLS)
			if sig.FingerprintPath != "" && sig.FingerprintMatch != "" {
				confirmed, _ := fingerprint(ctx, endpoint, sig.FingerprintPath, sig.FingerprintMatch, httpTimeout)
				if !confirmed {
					continue
				}
			}

			status, missing := determineStatus(sig)
			results = append(results, DiscoveredService{
				Name:        sig.Name,
				DisplayName: sig.DisplayName,
				Endpoint:    endpoint,
				Method:      "dns",
				Status:      status,
				SetupHint:   fmt.Sprintf("[dns:%s] %s", entry.hostname, sig.SetupHint),
				Credentials: missing,
			})
			break
		}
	}

	return results
}
