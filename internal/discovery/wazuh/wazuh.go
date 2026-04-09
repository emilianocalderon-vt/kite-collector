package wazuh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safenet"
)

const (
	clientTimeout   = 30 * time.Second
	maxPageSize     = 500
	maxConcurrency  = 10
	maxResponseBody = 10 << 20 // 10 MB
)

// Wazuh implements discovery.Source for the Wazuh Manager API.
type Wazuh struct {
	baseURL string // overridable in tests
}

// New returns a new Wazuh discovery source.
func New() *Wazuh { return &Wazuh{} }

// Name returns the stable identifier for this source.
func (w *Wazuh) Name() string { return "wazuh" }

// Discover enumerates all Wazuh agents and enriches them with package,
// vulnerability, SCA, port, and network interface data.
func (w *Wazuh) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	endpoint := w.baseURL
	if endpoint == "" {
		endpoint = toString(cfg["endpoint"])
	}
	if endpoint == "" {
		endpoint = os.Getenv("KITE_WAZUH_ENDPOINT")
	}
	username := os.Getenv("KITE_WAZUH_USERNAME")
	password := os.Getenv("KITE_WAZUH_PASSWORD")

	if endpoint == "" || username == "" || password == "" {
		return nil, fmt.Errorf("wazuh: KITE_WAZUH_ENDPOINT, KITE_WAZUH_USERNAME, KITE_WAZUH_PASSWORD required")
	}

	// Validate user-provided endpoints (skip for test override via baseURL).
	if w.baseURL == "" {
		valOpts := []safenet.Option{safenet.AllowPrivate()}
		if safenet.ParseBoolEnv("KITE_WAZUH_INSECURE") {
			valOpts = append(valOpts, safenet.AllowHTTP())
		}
		u, verr := safenet.ValidateEndpoint(endpoint, valOpts...)
		if verr != nil {
			return nil, fmt.Errorf("wazuh: %w", verr)
		}
		endpoint = strings.TrimRight(u.String(), "/")
	} else {
		endpoint = strings.TrimRight(endpoint, "/")
	}

	slog.Info("wazuh: starting discovery", "endpoint", sanitizeLogValue(endpoint)) //#nosec G706 -- sanitized via sanitizeLogValue

	tlsCfg, err := safenet.TLSConfig("KITE_WAZUH_INSECURE", "KITE_WAZUH_CA_CERT")
	if err != nil {
		return nil, fmt.Errorf("wazuh: %w", err)
	}
	httpClient := &http.Client{
		Timeout:   clientTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	auth := newAuth(endpoint, username, password, httpClient)
	client := &wazuhClient{auth: auth, http: httpClient, base: endpoint}

	// Warn about default credentials (CWE-1393). Password is never logged.
	if auth.isDefaultCredentials() {
		slog.Warn("wazuh: API uses default credentials — change them immediately (CWE-1393)")
	}

	// Read collection flags from config.
	collectPkgs := boolCfg(cfg, "collect_packages", true)
	collectVulns := boolCfg(cfg, "collect_vulnerabilities", true)
	collectSCA := boolCfg(cfg, "collect_sca", false)
	collectPorts := boolCfg(cfg, "collect_ports", false)
	collectIfaces := boolCfg(cfg, "collect_interfaces", false)
	maxAgents := intCfg(cfg, "max_agents", 0)

	// 1. List all agents.
	agents, err := client.listAllAgents(ctx)
	if err != nil {
		return nil, fmt.Errorf("wazuh: list agents: %w", err)
	}

	slog.Info("wazuh: agents retrieved", "count", len(agents))

	if maxAgents > 0 && len(agents) > maxAgents {
		agents = agents[:maxAgents]
	}

	// 2. Enrich each agent concurrently.
	type enrichedAgent struct {
		agent   wazuhAgent
		pkgs    []wazuhPackage
		vulns   []wazuhVulnerability
		sca     []wazuhSCAPolicy
		checks  map[string][]wazuhSCACheck
		ports   []wazuhPort
		ifaces  []wazuhNetIface
		addrs   []wazuhNetAddr
		defCred bool // whether default credentials were used
	}

	results := make([]enrichedAgent, len(agents))
	sem := make(chan struct{}, maxConcurrency)

	var wg sync.WaitGroup
	for i, ag := range agents {
		if ctx.Err() != nil {
			break
		}

		results[i].agent = ag
		results[i].defCred = auth.isDefaultCredentials()

		// Skip enrichment for disconnected/never_connected agents.
		if ag.Status != "active" && ag.Status != "pending" {
			continue
		}

		safenet.SafeGo(&wg, slog.Default(), fmt.Sprintf("wazuh-enrich-%s", ag.ID), func() {
			sem <- struct{}{}
			defer func() { <-sem }()

			rctx, cancel := safenet.WithResourceDeadline(ctx, 60*time.Second)
			defer cancel()

			if collectPkgs {
				pkgs, pkgErr := client.listAllPackages(rctx, ag.ID)
				if pkgErr != nil {
					slog.Warn("wazuh: packages failed", "agent", ag.ID, "error", pkgErr)
				} else {
					results[i].pkgs = pkgs
				}
			}

			if collectVulns {
				vulns, vulnErr := client.listAllVulnerabilities(rctx, ag.ID)
				if vulnErr != nil {
					slog.Warn("wazuh: vulnerabilities failed", "agent", ag.ID, "error", vulnErr)
				} else {
					results[i].vulns = vulns
				}
			}

			if collectSCA {
				policies, scaErr := client.listSCAPolicies(rctx, ag.ID)
				if scaErr != nil {
					slog.Warn("wazuh: SCA policies failed", "agent", ag.ID, "error", scaErr)
				} else {
					results[i].sca = policies
					results[i].checks = make(map[string][]wazuhSCACheck)
					for _, p := range policies {
						checks, chkErr := client.listSCAChecks(rctx, ag.ID, p.PolicyID)
						if chkErr != nil {
							slog.Warn("wazuh: SCA checks failed",
								"agent", ag.ID, "policy", p.PolicyID, "error", chkErr)
						} else {
							results[i].checks[p.PolicyID] = checks
						}
					}
				}
			}

			if collectPorts {
				ports, portErr := client.listPorts(rctx, ag.ID)
				if portErr != nil {
					slog.Warn("wazuh: ports failed", "agent", ag.ID, "error", portErr)
				} else {
					results[i].ports = ports
				}
			}

			if collectIfaces {
				nifaces, ifErr := client.listNetInterfaces(rctx, ag.ID)
				if ifErr != nil {
					slog.Warn("wazuh: interfaces failed", "agent", ag.ID, "error", ifErr)
				} else {
					results[i].ifaces = nifaces
				}
				naddrs, addrErr := client.listNetAddresses(rctx, ag.ID)
				if addrErr != nil {
					slog.Warn("wazuh: addresses failed", "agent", ag.ID, "error", addrErr)
				} else {
					results[i].addrs = naddrs
				}
			}
		})
	}
	wg.Wait()

	// 3. Convert to assets.
	now := time.Now().UTC()
	assets := make([]model.Asset, 0, len(results))

	for _, e := range results {
		asset := agentToAsset(e.agent, e.pkgs, e.vulns, e.sca, e.checks,
			e.ports, e.ifaces, e.addrs, e.defCred, now)
		assets = append(assets, asset)
	}

	slog.Info("wazuh: discovery complete", "assets", len(assets))
	return assets, nil
}

// -------------------------------------------------------------------------
// HTTP client
// -------------------------------------------------------------------------

type wazuhClient struct {
	auth *wazuhAuth
	http *http.Client
	base string
}

// doGet performs an authenticated GET request. On 401, it refreshes the
// token and retries once.
func (c *wazuhClient) doGet(ctx context.Context, path string) ([]byte, error) {
	for attempt := range 2 {
		token, err := c.auth.getToken(ctx)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
		if err != nil {
			return nil, fmt.Errorf("wazuh: build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := c.http.Do(req) //#nosec G107 -- URL from user-configured endpoint
		if err != nil {
			return nil, fmt.Errorf("wazuh: %w", err)
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(maxResponseBody)))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("wazuh: read body: %w", readErr)
		}

		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			slog.Debug("wazuh: token expired, refreshing")
			c.auth.invalidateToken()
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("wazuh: HTTP %d: %s", resp.StatusCode, truncateStr(string(body), 200))
		}

		return body, nil
	}

	return nil, fmt.Errorf("wazuh: authentication failed after token refresh")
}

// -------------------------------------------------------------------------
// Paginated list helpers
// -------------------------------------------------------------------------

// wazuhResponse is the standard Wazuh API response envelope.
type wazuhResponse struct {
	Data struct {
		AffectedItems      json.RawMessage `json:"affected_items"`
		TotalAffectedItems int             `json:"total_affected_items"`
	} `json:"data"`
	Error int `json:"error"`
}

func (c *wazuhClient) listPaginated(ctx context.Context, path string) ([]json.RawMessage, error) {
	var all []json.RawMessage
	offset := 0
	guard := safenet.NewPaginationGuard()

	for {
		if err := guard.Next(); err != nil {
			return all, err
		}
		if ctx.Err() != nil {
			return all, ctx.Err()
		}

		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		pagePath := fmt.Sprintf("%s%soffset=%d&limit=%d", path, sep, offset, maxPageSize)

		body, err := c.doGet(ctx, pagePath)
		if err != nil {
			return all, err
		}

		var resp wazuhResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return all, fmt.Errorf("wazuh: decode response: %w", err)
		}

		if resp.Error != 0 {
			return all, fmt.Errorf("wazuh: API error %d", resp.Error)
		}

		var items []json.RawMessage
		if err := json.Unmarshal(resp.Data.AffectedItems, &items); err != nil {
			return all, fmt.Errorf("wazuh: decode items: %w", err)
		}

		all = append(all, items...)

		if len(all) >= resp.Data.TotalAffectedItems || len(items) == 0 {
			break
		}
		offset += len(items)
	}

	return all, nil
}

// -------------------------------------------------------------------------
// Agent listing
// -------------------------------------------------------------------------

type wazuhAgent struct {
	OS struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Platform string `json:"platform"`
		Arch     string `json:"arch"`
	} `json:"os"`
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	IP            string   `json:"ip"`
	Status        string   `json:"status"`
	Version       string   `json:"version"`
	DateAdd       string   `json:"dateAdd"`
	LastKeepAlive string   `json:"lastKeepAlive"`
	NodeName      string   `json:"node_name"`
	Group         []string `json:"group"`
}

func (c *wazuhClient) listAllAgents(ctx context.Context) ([]wazuhAgent, error) {
	items, err := c.listPaginated(ctx, "/agents")
	if err != nil {
		return nil, err
	}

	agents := make([]wazuhAgent, 0, len(items))
	for _, item := range items {
		var ag wazuhAgent
		if err := json.Unmarshal(item, &ag); err != nil {
			slog.Warn("wazuh: skip agent with invalid JSON", "error", err)
			continue
		}
		agents = append(agents, ag)
	}
	return agents, nil
}

// -------------------------------------------------------------------------
// Package listing (syscollector)
// -------------------------------------------------------------------------

type wazuhPackage struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Vendor       string `json:"vendor"`
	Architecture string `json:"architecture"`
	Format       string `json:"format"`
}

func (c *wazuhClient) listAllPackages(ctx context.Context, agentID string) ([]wazuhPackage, error) {
	safeID, err := safenet.SanitizePathSegment(agentID)
	if err != nil {
		return nil, fmt.Errorf("wazuh: unsafe agent ID: %w", err)
	}
	items, err := c.listPaginated(ctx, fmt.Sprintf("/syscollector/%s/packages", safeID))
	if err != nil {
		return nil, err
	}

	pkgs := make([]wazuhPackage, 0, len(items))
	for _, item := range items {
		var pkg wazuhPackage
		if err := json.Unmarshal(item, &pkg); err != nil {
			continue
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs, nil
}

// -------------------------------------------------------------------------
// Vulnerability listing
// -------------------------------------------------------------------------

type wazuhVulnerability struct {
	Name          string  `json:"name"`
	Version       string  `json:"version"`
	CVE           string  `json:"cve"`
	Severity      string  `json:"severity"`
	Status        string  `json:"status"`
	DetectionTime string  `json:"detection_time"`
	CVSS3Score    float64 `json:"cvss3_score"`
	CVSS2Score    float64 `json:"cvss2_score"`
}

func (c *wazuhClient) listAllVulnerabilities(ctx context.Context, agentID string) ([]wazuhVulnerability, error) {
	safeID, err := safenet.SanitizePathSegment(agentID)
	if err != nil {
		return nil, fmt.Errorf("wazuh: unsafe agent ID: %w", err)
	}
	items, err := c.listPaginated(ctx, fmt.Sprintf("/vulnerability/%s", safeID))
	if err != nil {
		return nil, err
	}

	vulns := make([]wazuhVulnerability, 0, len(items))
	for _, item := range items {
		var v wazuhVulnerability
		if err := json.Unmarshal(item, &v); err != nil {
			continue
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}

// -------------------------------------------------------------------------
// SCA listing
// -------------------------------------------------------------------------

type wazuhSCAPolicy struct {
	PolicyID    string  `json:"policy_id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Score       float64 `json:"score"`
	Pass        int     `json:"pass"`
	Fail        int     `json:"fail"`
}

type wazuhSCACheck struct {
	Title       string               `json:"title"`
	Result      string               `json:"result"`
	Rationale   string               `json:"rationale"`
	Remediation string               `json:"remediation"`
	Description string               `json:"description"`
	Compliance  []wazuhSCACompliance `json:"compliance"`
	ID          int                  `json:"id"`
}

type wazuhSCACompliance struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (c *wazuhClient) listSCAPolicies(ctx context.Context, agentID string) ([]wazuhSCAPolicy, error) {
	safeID, err := safenet.SanitizePathSegment(agentID)
	if err != nil {
		return nil, fmt.Errorf("wazuh: unsafe agent ID: %w", err)
	}
	items, err := c.listPaginated(ctx, fmt.Sprintf("/sca/%s", safeID))
	if err != nil {
		return nil, err
	}

	policies := make([]wazuhSCAPolicy, 0, len(items))
	for _, item := range items {
		var p wazuhSCAPolicy
		if err := json.Unmarshal(item, &p); err != nil {
			continue
		}
		policies = append(policies, p)
	}
	return policies, nil
}

func (c *wazuhClient) listSCAChecks(ctx context.Context, agentID, policyID string) ([]wazuhSCACheck, error) {
	safeAgentID, err := safenet.SanitizePathSegment(agentID)
	if err != nil {
		return nil, fmt.Errorf("wazuh: unsafe agent ID: %w", err)
	}
	safePolicyID, err := safenet.SanitizePathSegment(policyID)
	if err != nil {
		return nil, fmt.Errorf("wazuh: unsafe policy ID: %w", err)
	}
	items, err := c.listPaginated(ctx, fmt.Sprintf("/sca/%s/checks/%s", safeAgentID, safePolicyID))
	if err != nil {
		return nil, err
	}

	checks := make([]wazuhSCACheck, 0, len(items))
	for _, item := range items {
		var ch wazuhSCACheck
		if err := json.Unmarshal(item, &ch); err != nil {
			continue
		}
		checks = append(checks, ch)
	}
	return checks, nil
}

// -------------------------------------------------------------------------
// Port listing (syscollector)
// -------------------------------------------------------------------------

type wazuhPort struct {
	Protocol string `json:"protocol"`
	Process  string `json:"process"`
	Local    struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"local"`
	PID int `json:"pid"`
}

func (c *wazuhClient) listPorts(ctx context.Context, agentID string) ([]wazuhPort, error) {
	safeID, err := safenet.SanitizePathSegment(agentID)
	if err != nil {
		return nil, fmt.Errorf("wazuh: unsafe agent ID: %w", err)
	}
	items, err := c.listPaginated(ctx, fmt.Sprintf("/syscollector/%s/ports", safeID))
	if err != nil {
		return nil, err
	}

	ports := make([]wazuhPort, 0, len(items))
	for _, item := range items {
		var p wazuhPort
		if err := json.Unmarshal(item, &p); err != nil {
			continue
		}
		ports = append(ports, p)
	}
	return ports, nil
}

// -------------------------------------------------------------------------
// Network interface + address listing (syscollector)
// -------------------------------------------------------------------------

type wazuhNetIface struct {
	Name  string `json:"name"`
	MAC   string `json:"mac"`
	State string `json:"state"`
	Type  string `json:"type"`
	MTU   int    `json:"mtu"`
}

type wazuhNetAddr struct {
	Iface     string `json:"iface"`
	Proto     string `json:"proto"`
	Address   string `json:"address"`
	Netmask   string `json:"netmask"`
	Broadcast string `json:"broadcast"`
}

func (c *wazuhClient) listNetInterfaces(ctx context.Context, agentID string) ([]wazuhNetIface, error) {
	safeID, err := safenet.SanitizePathSegment(agentID)
	if err != nil {
		return nil, fmt.Errorf("wazuh: unsafe agent ID: %w", err)
	}
	items, err := c.listPaginated(ctx, fmt.Sprintf("/syscollector/%s/netiface", safeID))
	if err != nil {
		return nil, err
	}

	ifaces := make([]wazuhNetIface, 0, len(items))
	for _, item := range items {
		var iface wazuhNetIface
		if err := json.Unmarshal(item, &iface); err != nil {
			continue
		}
		ifaces = append(ifaces, iface)
	}
	return ifaces, nil
}

func (c *wazuhClient) listNetAddresses(ctx context.Context, agentID string) ([]wazuhNetAddr, error) {
	safeID, err := safenet.SanitizePathSegment(agentID)
	if err != nil {
		return nil, fmt.Errorf("wazuh: unsafe agent ID: %w", err)
	}
	items, err := c.listPaginated(ctx, fmt.Sprintf("/syscollector/%s/netaddr", safeID))
	if err != nil {
		return nil, err
	}

	addrs := make([]wazuhNetAddr, 0, len(items))
	for _, item := range items {
		var addr wazuhNetAddr
		if err := json.Unmarshal(item, &addr); err != nil {
			continue
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

// -------------------------------------------------------------------------
// Asset mapping
// -------------------------------------------------------------------------

func agentToAsset(
	ag wazuhAgent,
	pkgs []wazuhPackage,
	vulns []wazuhVulnerability,
	scaPolicies []wazuhSCAPolicy,
	scaChecks map[string][]wazuhSCACheck,
	ports []wazuhPort,
	ifaces []wazuhNetIface,
	addrs []wazuhNetAddr,
	defaultCreds bool,
	now time.Time,
) model.Asset {
	hostname := ag.Name
	if hostname == "" {
		hostname = ag.ID
	}

	assetType := model.AssetTypeServer
	if isDesktopOS(ag.OS.Platform, ag.OS.Name) {
		assetType = model.AssetTypeWorkstation
	}

	tags := map[string]any{
		"wazuh_agent_id": ag.ID,
		"ip":             ag.IP,
		"status":         ag.Status,
	}

	if ag.Version != "" {
		tags["wazuh_version"] = ag.Version
	}
	if ag.NodeName != "" {
		tags["wazuh_node"] = ag.NodeName
	}
	if len(ag.Group) > 0 {
		tags["groups"] = ag.Group
	}

	// Flag disconnected agents (R9).
	if ag.Status == "disconnected" || ag.Status == "never_connected" {
		tags["stale"] = true
		tags["warning"] = fmt.Sprintf("agent %s — asset data may be outdated", ag.Status)
	}

	// Default credential warning (R3).
	if defaultCreds {
		tags["default_credentials_warning"] = "Wazuh API uses default credentials (CWE-1393)"
	}

	// Installed software with CPE (R5, R6).
	if len(pkgs) > 0 {
		swList := make([]map[string]any, 0, len(pkgs))
		for _, pkg := range pkgs {
			cpe := software.BuildCPE23WithArch(pkg.Vendor, pkg.Name, pkg.Version, pkg.Architecture)
			sw := map[string]any{
				"name":    pkg.Name,
				"version": pkg.Version,
				"cpe":     cpe,
			}
			if pkg.Vendor != "" {
				sw["vendor"] = pkg.Vendor
			}
			if pkg.Architecture != "" {
				sw["arch"] = pkg.Architecture
			}
			if pkg.Format != "" {
				sw["package_manager"] = pkg.Format
			}
			swList = append(swList, sw)
		}
		tags["installed_software"] = swList
	}

	// Detected CVEs (R7).
	if len(vulns) > 0 {
		cveList := make([]map[string]any, 0, len(vulns))
		for _, v := range vulns {
			cve := map[string]any{
				"cve":      v.CVE,
				"name":     v.Name,
				"version":  v.Version,
				"severity": v.Severity,
				"status":   v.Status,
			}
			if v.CVSS3Score > 0 {
				cve["cvss3_score"] = v.CVSS3Score
			}
			if v.CVSS2Score > 0 {
				cve["cvss2_score"] = v.CVSS2Score
			}
			if v.DetectionTime != "" {
				cve["detection_time"] = v.DetectionTime
			}
			cveList = append(cveList, cve)
		}
		tags["detected_cves"] = cveList
	}

	// SCA findings (Phase 2 — R12).
	if len(scaPolicies) > 0 {
		scaList := make([]map[string]any, 0, len(scaPolicies))
		for _, policy := range scaPolicies {
			entry := map[string]any{
				"policy_id": policy.PolicyID,
				"name":      policy.Name,
				"pass":      policy.Pass,
				"fail":      policy.Fail,
				"score":     policy.Score,
			}
			if checks, ok := scaChecks[policy.PolicyID]; ok {
				failed := make([]map[string]any, 0)
				for _, ch := range checks {
					if ch.Result != "failed" {
						continue
					}
					chk := map[string]any{
						"id":          ch.ID,
						"title":       ch.Title,
						"remediation": ch.Remediation,
					}
					for _, comp := range ch.Compliance {
						if comp.Key == "cis" || comp.Key == "cis_csc" {
							chk["cis_control"] = comp.Value
							break
						}
					}
					failed = append(failed, chk)
				}
				if len(failed) > 0 {
					entry["failed_checks"] = failed
				}
			}
			scaList = append(scaList, entry)
		}
		tags["sca_findings"] = scaList
	}

	// Open ports (Phase 2).
	if len(ports) > 0 {
		portList := make([]map[string]any, 0, len(ports))
		for _, p := range ports {
			portList = append(portList, map[string]any{
				"protocol": p.Protocol,
				"port":     p.Local.Port,
				"ip":       p.Local.IP,
				"process":  p.Process,
			})
		}
		tags["open_ports"] = portList
	}

	// Network interfaces (Phase 2).
	if len(ifaces) > 0 {
		addrMap := make(map[string][]map[string]string)
		for _, a := range addrs {
			addrMap[a.Iface] = append(addrMap[a.Iface], map[string]string{
				"proto":   a.Proto,
				"address": a.Address,
				"netmask": a.Netmask,
			})
		}

		ifaceList := make([]map[string]any, 0, len(ifaces))
		for _, iface := range ifaces {
			entry := map[string]any{
				"name":  iface.Name,
				"mac":   iface.MAC,
				"state": iface.State,
			}
			if ifAddrs, ok := addrMap[iface.Name]; ok {
				entry["addresses"] = ifAddrs
			}
			ifaceList = append(ifaceList, entry)
		}
		tags["network_interfaces"] = ifaceList
	}

	// Authorization hint from groups (Phase 2 — R13).
	if groupHintsAuthorized(ag.Group) {
		tags["authorization_hint"] = "authorized"
	}

	tagsJSON, _ := json.Marshal(tags)

	firstSeen := now
	if t, err := time.Parse(time.RFC3339, ag.DateAdd); err == nil {
		firstSeen = t
	}
	lastSeen := now
	if t, err := time.Parse(time.RFC3339, ag.LastKeepAlive); err == nil {
		lastSeen = t
	}

	osVersion := ag.OS.Name
	if ag.OS.Version != "" {
		osVersion = ag.OS.Name + " " + ag.OS.Version
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        hostname,
		AssetType:       assetType,
		OSFamily:        ag.OS.Platform,
		OSVersion:       osVersion,
		Architecture:    ag.OS.Arch,
		DiscoverySource: "wazuh",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      lastSeen,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedManaged, // Wazuh agent present = managed
		Tags:            string(tagsJSON),
	}
	asset.ComputeNaturalKey()
	return asset
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

func isDesktopOS(platform, name string) bool {
	p := strings.ToLower(platform)
	n := strings.ToLower(name)
	return p == "windows" || p == "darwin" ||
		strings.Contains(n, "desktop") ||
		strings.Contains(n, "workstation")
}

func groupHintsAuthorized(groups []string) bool {
	for _, g := range groups {
		lower := strings.ToLower(g)
		if lower == "authorized" || lower == "managed" ||
			lower == "production" || lower == "prod" {
			return true
		}
	}
	return false
}

func boolCfg(cfg map[string]any, key string, def bool) bool {
	if cfg == nil {
		return def
	}
	if v, ok := cfg[key].(bool); ok {
		return v
	}
	return def
}

func intCfg(cfg map[string]any, key string, def int) int {
	if cfg == nil {
		return def
	}
	switch v := cfg[key].(type) {
	case int:
		return v
	case float64:
		return int(v)
	default:
		return def
	}
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func sanitizeLogValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}

// Compile-time interface check.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*Wazuh)(nil)
