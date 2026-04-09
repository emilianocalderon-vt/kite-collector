package wazuh

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// -------------------------------------------------------------------------
// Mock Wazuh API server
// -------------------------------------------------------------------------

// wazuhAPIResponse builds a standard Wazuh API response envelope.
func wazuhAPIResponse(items any, total int) []byte {
	itemsJSON, _ := json.Marshal(items)
	resp := map[string]any{
		"data": map[string]any{
			"affected_items":       json.RawMessage(itemsJSON),
			"total_affected_items": total,
			"total_failed_items":   0,
			"failed_items":         []any{},
		},
		"error": 0,
	}
	data, _ := json.Marshal(resp)
	return data
}

func newMockWazuhAPI(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// Auth endpoint.
	mux.HandleFunc("/security/user/authenticate", func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "admin" || p != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resp := map[string]any{
			"data": map[string]any{"token": "mock-jwt-token"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	// Agents listing.
	mux.HandleFunc("/agents", func(w http.ResponseWriter, r *http.Request) {
		if !checkBearer(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		agents := []wazuhAgent{
			{
				ID:     "001",
				Name:   "web-server",
				IP:     "10.0.0.5",
				Status: "active",
				OS: struct {
					Name     string `json:"name"`
					Version  string `json:"version"`
					Platform string `json:"platform"`
					Arch     string `json:"arch"`
				}{
					Name:     "Ubuntu",
					Version:  "22.04.3 LTS",
					Platform: "ubuntu",
					Arch:     "x86_64",
				},
				Version:       "Wazuh v4.7.2",
				DateAdd:       "2025-10-15T10:30:45Z",
				LastKeepAlive: "2026-04-06T14:22:33Z",
				Group:         []string{"linux", "web-servers", "production"},
				NodeName:      "node01",
			},
			{
				ID:     "002",
				Name:   "db-server",
				IP:     "10.0.0.6",
				Status: "disconnected",
				OS: struct {
					Name     string `json:"name"`
					Version  string `json:"version"`
					Platform string `json:"platform"`
					Arch     string `json:"arch"`
				}{
					Name:     "CentOS",
					Version:  "8",
					Platform: "centos",
					Arch:     "x86_64",
				},
				Version:       "Wazuh v4.7.1",
				DateAdd:       "2025-08-01T09:00:00Z",
				LastKeepAlive: "2026-03-01T00:00:00Z",
				Group:         []string{"linux", "databases"},
				NodeName:      "node01",
			},
			{
				ID:     "003",
				Name:   "win-desktop",
				IP:     "10.0.0.10",
				Status: "active",
				OS: struct {
					Name     string `json:"name"`
					Version  string `json:"version"`
					Platform string `json:"platform"`
					Arch     string `json:"arch"`
				}{
					Name:     "Microsoft Windows 11 Pro",
					Version:  "10.0.22631",
					Platform: "windows",
					Arch:     "x86_64",
				},
				Version:       "Wazuh v4.7.2",
				DateAdd:       "2025-12-01T08:00:00Z",
				LastKeepAlive: "2026-04-06T14:00:00Z",
			},
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(wazuhAPIResponse(agents, len(agents)))
	})

	// Packages for agent 001.
	mux.HandleFunc("/syscollector/001/packages", func(w http.ResponseWriter, r *http.Request) {
		if !checkBearer(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		pkgs := []wazuhPackage{
			{Name: "curl", Version: "7.88.1", Vendor: "Haxx", Architecture: "x86_64", Format: "deb"},
			{Name: "openssl", Version: "3.0.2", Vendor: "OpenSSL", Architecture: "x86_64", Format: "deb"},
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(wazuhAPIResponse(pkgs, len(pkgs)))
	})

	// Packages for agent 003.
	mux.HandleFunc("/syscollector/003/packages", func(w http.ResponseWriter, r *http.Request) {
		if !checkBearer(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(wazuhAPIResponse([]wazuhPackage{}, 0))
	})

	// Vulnerabilities for agent 001.
	mux.HandleFunc("/vulnerability/001", func(w http.ResponseWriter, r *http.Request) {
		if !checkBearer(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		vulns := []wazuhVulnerability{
			{
				Name:          "curl",
				Version:       "7.88.1",
				CVE:           "CVE-2023-38545",
				Severity:      "Critical",
				CVSS3Score:    9.8,
				Status:        "VALID",
				DetectionTime: "2026-04-06T12:00:00Z",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(wazuhAPIResponse(vulns, len(vulns)))
	})

	// Vulnerabilities for agent 003.
	mux.HandleFunc("/vulnerability/003", func(w http.ResponseWriter, r *http.Request) {
		if !checkBearer(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(wazuhAPIResponse([]wazuhVulnerability{}, 0))
	})

	// SCA for agent 001.
	mux.HandleFunc("/sca/001", func(w http.ResponseWriter, r *http.Request) {
		if !checkBearer(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Only respond for /sca/001 (no checks subpath).
		if strings.Contains(r.URL.Path, "/checks/") {
			return
		}
		policies := []wazuhSCAPolicy{
			{PolicyID: "cis_ubuntu22-04", Name: "CIS Ubuntu 22.04", Pass: 45, Fail: 3, Score: 93.75},
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(wazuhAPIResponse(policies, len(policies)))
	})

	// SCA checks for agent 001 / cis_ubuntu22-04.
	mux.HandleFunc("/sca/001/checks/cis_ubuntu22-04", func(w http.ResponseWriter, r *http.Request) {
		if !checkBearer(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		checks := []wazuhSCACheck{
			{
				ID:          1500,
				Title:       "Ensure SSH root login is disabled",
				Result:      "failed",
				Rationale:   "Disallowing root logins over SSH requires system admins to authenticate using their own individual account.",
				Remediation: "Set PermitRootLogin to no in /etc/ssh/sshd_config",
				Compliance:  []wazuhSCACompliance{{Key: "cis", Value: "5.2.8"}},
			},
			{
				ID:     1501,
				Title:  "Ensure password expiration is configured",
				Result: "passed",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(wazuhAPIResponse(checks, len(checks)))
	})

	// Ports for agent 001.
	mux.HandleFunc("/syscollector/001/ports", func(w http.ResponseWriter, r *http.Request) {
		if !checkBearer(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ports := []wazuhPort{
			{Protocol: "tcp", Process: "nginx", Local: struct {
				IP   string `json:"ip"`
				Port int    `json:"port"`
			}{IP: "0.0.0.0", Port: 443}, PID: 1234},
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(wazuhAPIResponse(ports, len(ports)))
	})

	// Network interfaces for agent 001.
	mux.HandleFunc("/syscollector/001/netiface", func(w http.ResponseWriter, r *http.Request) {
		if !checkBearer(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ifaces := []wazuhNetIface{
			{Name: "eth0", MAC: "00:11:22:33:44:55", MTU: 1500, State: "up", Type: "ethernet"},
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(wazuhAPIResponse(ifaces, len(ifaces)))
	})

	// Network addresses for agent 001.
	mux.HandleFunc("/syscollector/001/netaddr", func(w http.ResponseWriter, r *http.Request) {
		if !checkBearer(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		addrs := []wazuhNetAddr{
			{Iface: "eth0", Proto: "ipv4", Address: "10.0.0.5", Netmask: "255.255.255.0", Broadcast: "10.0.0.255"},
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(wazuhAPIResponse(addrs, len(addrs)))
	})

	return httptest.NewServer(mux)
}

func checkBearer(r *http.Request) bool {
	return r.Header.Get("Authorization") == "Bearer mock-jwt-token"
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

func TestWazuh_Name(t *testing.T) {
	w := New()
	assert.Equal(t, "wazuh", w.Name())
}

func TestWazuh_Discover_Success(t *testing.T) {
	srv := newMockWazuhAPI(t)
	defer srv.Close()

	t.Setenv("KITE_WAZUH_ENDPOINT", srv.URL)
	t.Setenv("KITE_WAZUH_USERNAME", "admin")
	t.Setenv("KITE_WAZUH_PASSWORD", "secret")
	t.Setenv("KITE_WAZUH_INSECURE", "true")

	w := New()
	assets, err := w.Discover(context.Background(), map[string]any{
		"collect_packages":        true,
		"collect_vulnerabilities": true,
		"collect_sca":            true,
		"collect_ports":          true,
		"collect_interfaces":     true,
	})
	require.NoError(t, err)
	assert.Len(t, assets, 3, "3 agents = 3 assets")

	// Verify active agent.
	web := findAsset(assets, "web-server")
	require.NotNil(t, web)
	assert.Equal(t, model.AssetTypeServer, web.AssetType)
	assert.Equal(t, "wazuh", web.DiscoverySource)
	assert.Equal(t, "ubuntu", web.OSFamily)
	assert.Equal(t, "Ubuntu 22.04.3 LTS", web.OSVersion)
	assert.Equal(t, "x86_64", web.Architecture)
	assert.Equal(t, model.ManagedManaged, web.IsManaged)
	assert.Equal(t, model.AuthorizationUnknown, web.IsAuthorized)
	assert.NotEmpty(t, web.NaturalKey)

	var webTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(web.Tags), &webTags))
	assert.Equal(t, "001", webTags["wazuh_agent_id"])
	assert.Equal(t, "10.0.0.5", webTags["ip"])
	assert.Equal(t, "active", webTags["status"])
	assert.Equal(t, "Wazuh v4.7.2", webTags["wazuh_version"])
	assert.Equal(t, "node01", webTags["wazuh_node"])

	// Verify authorization hint from groups.
	assert.Equal(t, "authorized", webTags["authorization_hint"])

	// Verify installed software with CPE.
	sw, ok := webTags["installed_software"].([]any)
	require.True(t, ok)
	assert.Len(t, sw, 2)
	curl := sw[0].(map[string]any)
	assert.Equal(t, "curl", curl["name"])
	assert.Equal(t, "7.88.1", curl["version"])
	assert.Equal(t, "Haxx", curl["vendor"])
	assert.Contains(t, curl["cpe"], "cpe:2.3:a:haxx:curl:7.88.1:")

	// Verify detected CVEs.
	cves, ok := webTags["detected_cves"].([]any)
	require.True(t, ok)
	assert.Len(t, cves, 1)
	cve := cves[0].(map[string]any)
	assert.Equal(t, "CVE-2023-38545", cve["cve"])
	assert.Equal(t, "Critical", cve["severity"])
	assert.Equal(t, 9.8, cve["cvss3_score"])

	// Verify SCA findings.
	scaFindings, ok := webTags["sca_findings"].([]any)
	require.True(t, ok)
	assert.Len(t, scaFindings, 1)
	policy := scaFindings[0].(map[string]any)
	assert.Equal(t, "cis_ubuntu22-04", policy["policy_id"])
	assert.Equal(t, 93.75, policy["score"])
	failedChecks, ok := policy["failed_checks"].([]any)
	require.True(t, ok)
	assert.Len(t, failedChecks, 1)
	check := failedChecks[0].(map[string]any)
	assert.Equal(t, "Ensure SSH root login is disabled", check["title"])
	assert.Equal(t, "5.2.8", check["cis_control"])

	// Verify open ports.
	openPorts, ok := webTags["open_ports"].([]any)
	require.True(t, ok)
	assert.Len(t, openPorts, 1)
	port := openPorts[0].(map[string]any)
	assert.Equal(t, "tcp", port["protocol"])
	assert.Equal(t, float64(443), port["port"])
	assert.Equal(t, "nginx", port["process"])

	// Verify network interfaces.
	netIfaces, ok := webTags["network_interfaces"].([]any)
	require.True(t, ok)
	assert.Len(t, netIfaces, 1)
	eth0 := netIfaces[0].(map[string]any)
	assert.Equal(t, "eth0", eth0["name"])
	assert.Equal(t, "00:11:22:33:44:55", eth0["mac"])

	// Verify disconnected agent.
	db := findAsset(assets, "db-server")
	require.NotNil(t, db)
	var dbTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(db.Tags), &dbTags))
	assert.Equal(t, true, dbTags["stale"])
	assert.Contains(t, dbTags["warning"], "disconnected")
	// Disconnected agents should NOT have software/vulns (no enrichment).
	assert.Nil(t, dbTags["installed_software"])
	assert.Nil(t, dbTags["detected_cves"])

	// Verify Windows agent is classified as workstation.
	win := findAsset(assets, "win-desktop")
	require.NotNil(t, win)
	assert.Equal(t, model.AssetTypeWorkstation, win.AssetType)
	assert.Equal(t, "windows", win.OSFamily)
}

func TestWazuh_Discover_MissingCredentials(t *testing.T) {
	t.Setenv("KITE_WAZUH_ENDPOINT", "")
	t.Setenv("KITE_WAZUH_USERNAME", "")
	t.Setenv("KITE_WAZUH_PASSWORD", "")

	w := New()
	_, err := w.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestWazuh_Discover_AuthFailure(t *testing.T) {
	srv := newMockWazuhAPI(t)
	defer srv.Close()

	t.Setenv("KITE_WAZUH_ENDPOINT", srv.URL)
	t.Setenv("KITE_WAZUH_USERNAME", "admin")
	t.Setenv("KITE_WAZUH_PASSWORD", "wrong")
	t.Setenv("KITE_WAZUH_INSECURE", "true")

	w := New()
	_, err := w.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 401")
}

func TestWazuh_Discover_EndpointFromConfig(t *testing.T) {
	srv := newMockWazuhAPI(t)
	defer srv.Close()

	t.Setenv("KITE_WAZUH_ENDPOINT", "")
	t.Setenv("KITE_WAZUH_USERNAME", "admin")
	t.Setenv("KITE_WAZUH_PASSWORD", "secret")
	t.Setenv("KITE_WAZUH_INSECURE", "true")

	w := New()
	assets, err := w.Discover(context.Background(), map[string]any{
		"endpoint": srv.URL,
	})
	require.NoError(t, err)
	assert.Len(t, assets, 3)
}

func TestWazuh_Discover_MaxAgents(t *testing.T) {
	srv := newMockWazuhAPI(t)
	defer srv.Close()

	t.Setenv("KITE_WAZUH_ENDPOINT", srv.URL)
	t.Setenv("KITE_WAZUH_USERNAME", "admin")
	t.Setenv("KITE_WAZUH_PASSWORD", "secret")
	t.Setenv("KITE_WAZUH_INSECURE", "true")

	w := New()
	assets, err := w.Discover(context.Background(), map[string]any{
		"max_agents":              1,
		"collect_packages":        false,
		"collect_vulnerabilities": false,
	})
	require.NoError(t, err)
	assert.Len(t, assets, 1, "max_agents=1 should limit to 1 asset")
}

func TestWazuh_Discover_BaseURLOverride(t *testing.T) {
	srv := newMockWazuhAPI(t)
	defer srv.Close()

	t.Setenv("KITE_WAZUH_USERNAME", "admin")
	t.Setenv("KITE_WAZUH_PASSWORD", "secret")

	w := &Wazuh{baseURL: srv.URL}
	assets, err := w.Discover(context.Background(), map[string]any{
		"collect_packages":        false,
		"collect_vulnerabilities": false,
	})
	require.NoError(t, err)
	assert.Len(t, assets, 3)
}

func TestIsDesktopOS(t *testing.T) {
	assert.True(t, isDesktopOS("windows", "Microsoft Windows 11"))
	assert.True(t, isDesktopOS("darwin", "macOS"))
	assert.True(t, isDesktopOS("ubuntu", "Ubuntu Desktop"))
	assert.False(t, isDesktopOS("ubuntu", "Ubuntu"))
	assert.False(t, isDesktopOS("centos", "CentOS"))
}

func TestGroupHintsAuthorized(t *testing.T) {
	assert.True(t, groupHintsAuthorized([]string{"linux", "production"}))
	assert.True(t, groupHintsAuthorized([]string{"authorized"}))
	assert.True(t, groupHintsAuthorized([]string{"managed"}))
	assert.False(t, groupHintsAuthorized([]string{"linux", "web-servers"}))
	assert.False(t, groupHintsAuthorized(nil))
}

func TestBoolCfg(t *testing.T) {
	assert.True(t, boolCfg(nil, "key", true))
	assert.False(t, boolCfg(nil, "key", false))
	assert.True(t, boolCfg(map[string]any{"key": true}, "key", false))
	assert.False(t, boolCfg(map[string]any{"key": false}, "key", true))
	assert.True(t, boolCfg(map[string]any{}, "key", true))
}

func TestIntCfg(t *testing.T) {
	assert.Equal(t, 42, intCfg(nil, "key", 42))
	assert.Equal(t, 10, intCfg(map[string]any{"key": 10}, "key", 0))
	assert.Equal(t, 5, intCfg(map[string]any{"key": float64(5)}, "key", 0))
	assert.Equal(t, 99, intCfg(map[string]any{"key": "nope"}, "key", 99))
}

func TestTokenAutoRefreshOn401(t *testing.T) {
	authCalls := 0
	getCalls := 0

	mux := http.NewServeMux()
	mux.HandleFunc("/security/user/authenticate", func(w http.ResponseWriter, _ *http.Request) {
		authCalls++
		token := "token-v1"
		if authCalls > 1 {
			token = "token-v2"
		}
		resp := map[string]any{"data": map[string]any{"token": token}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/agents", func(w http.ResponseWriter, r *http.Request) {
		getCalls++
		authHeader := r.Header.Get("Authorization")
		// First call with token-v1 returns 401 (simulating expired token).
		if authHeader == "Bearer token-v1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Second call with token-v2 succeeds.
		if authHeader == "Bearer token-v2" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(wazuhAPIResponse([]wazuhAgent{}, 0))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv("KITE_WAZUH_USERNAME", "admin")
	t.Setenv("KITE_WAZUH_PASSWORD", "secret")

	w := &Wazuh{baseURL: srv.URL}
	assets, err := w.Discover(context.Background(), map[string]any{
		"collect_packages":        false,
		"collect_vulnerabilities": false,
	})
	require.NoError(t, err)
	assert.Empty(t, assets)

	// Auth should have been called twice (initial + refresh).
	assert.Equal(t, 2, authCalls, "should refresh token on 401")
	// GET /agents should have been attempted twice.
	assert.Equal(t, 2, getCalls, "should retry request after token refresh")
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func findAsset(assets []model.Asset, hostname string) *model.Asset {
	for i := range assets {
		if assets[i].Hostname == hostname {
			return &assets[i]
		}
	}
	return nil
}
