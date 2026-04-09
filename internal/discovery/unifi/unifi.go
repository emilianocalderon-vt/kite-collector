// Package unifi implements a discovery.Source that enumerates clients and
// network devices from UniFi APIs.
//
// Two authentication modes are supported:
//
//  1. Cloud API Key (recommended): set KITE_UNIFI_API_KEY.
//     Uses the official UniFi Site Manager API at api.ui.com.
//     Read-only, no MFA issues.
//
//  2. Local session auth: set KITE_UNIFI_ENDPOINT + KITE_UNIFI_USERNAME +
//     KITE_UNIFI_PASSWORD.  Authenticates directly to the controller on
//     your LAN.  Tries /api/auth/login (UDM/UniFi OS) first, falls back
//     to /api/login (legacy controller).
package unifi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safenet"
)

const (
	clientTimeout = 30 * time.Second
	cloudBaseURL  = "https://api.ui.com"
)

// UniFi implements discovery.Source for the UniFi Controller API.
type UniFi struct{}

// New returns a new UniFi discovery source.
func New() *UniFi { return &UniFi{} }

// Name returns the stable identifier for this source.
func (u *UniFi) Name() string { return "unifi" }

// Discover enumerates clients and devices from UniFi.
//
// Authentication priority:
//  1. KITE_UNIFI_API_KEY → cloud API (api.ui.com)
//  2. KITE_UNIFI_USERNAME + PASSWORD → local session auth
func (u *UniFi) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	apiKey := os.Getenv("KITE_UNIFI_API_KEY")
	if apiKey != "" {
		return u.discoverCloud(ctx, apiKey)
	}
	return u.discoverLocal(ctx, cfg)
}

// -------------------------------------------------------------------------
// Cloud API (api.ui.com with X-API-KEY)
// -------------------------------------------------------------------------

func (u *UniFi) discoverCloud(ctx context.Context, apiKey string) ([]model.Asset, error) {
	slog.Info("unifi: using cloud API (api.ui.com)")

	client := &cloudClient{
		apiKey: apiKey,
		http:   &http.Client{Timeout: clientTimeout},
	}

	now := time.Now().UTC()
	var assets []model.Asset

	// List hosts (consoles/controllers).
	hosts, err := client.listHosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("unifi cloud: list hosts: %w", err)
	}
	slog.Info("unifi: found hosts", "count", len(hosts))

	// List devices across all hosts.
	devices, err := client.listDevices(ctx)
	if err != nil {
		slog.Warn("unifi cloud: failed to list devices", "error", err)
	} else {
		for _, d := range devices {
			assets = append(assets, cloudDeviceToAsset(d, now))
		}
	}

	// Add hosts as assets.
	for _, h := range hosts {
		assets = append(assets, cloudHostToAsset(h, now))
	}

	slog.Info("unifi: cloud discovery complete", "assets", len(assets))
	return assets, nil
}

type cloudClient struct {
	http   *http.Client
	apiKey string
}

func (c *cloudClient) get(ctx context.Context, path string) ([]byte, error) {
	url := cloudBaseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf(
			"HTTP 401 — invalid API key. Generate one at unifi.ui.com → Settings → API Keys")
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("HTTP 429 — rate limited. Try again later")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	return body, nil
}

// Cloud API response types.

type cloudHostsResponse struct {
	Data []cloudHost `json:"data"`
}

type cloudHost struct {
	ID            string `json:"id"`
	HardwareID    string `json:"hardware_id"`
	Hostname      string `json:"reported_state__hostname"`
	Model         string `json:"hardware_type"`
	FirmwareVer   string `json:"reported_state__firmware"`
	IPAddress     string `json:"ip_address"`
	ControllerVer string `json:"reported_state__controller_version"`
	IsOnline      bool   `json:"is_blocked"`
}

type cloudDevicesResponse struct {
	Data []cloudDevice `json:"data"`
}

type cloudDevice struct {
	Name     string `json:"name"`
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Model    string `json:"model"`
	Firmware string `json:"firmware"`
	State    string `json:"state"`
	Type     string `json:"type"`
}

func (c *cloudClient) listHosts(ctx context.Context) ([]cloudHost, error) {
	body, err := c.get(ctx, "/ea/hosts")
	if err != nil {
		return nil, err
	}
	var resp cloudHostsResponse
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse hosts: %w", err)
	}
	return resp.Data, nil
}

func (c *cloudClient) listDevices(ctx context.Context) ([]cloudDevice, error) {
	body, err := c.get(ctx, "/ea/devices")
	if err != nil {
		return nil, err
	}
	var resp cloudDevicesResponse
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse devices: %w", err)
	}
	return resp.Data, nil
}

func cloudHostToAsset(h cloudHost, now time.Time) model.Asset {
	hostname := h.Hostname
	if hostname == "" {
		hostname = h.HardwareID
	}

	tags := map[string]any{
		"ip":             h.IPAddress,
		"model":          h.Model,
		"firmware":       h.FirmwareVer,
		"controller_ver": h.ControllerVer,
		"hardware_id":    h.HardwareID,
		"source":         "unifi_cloud",
	}
	tagsJSON, _ := json.Marshal(tags)

	return model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        hostname,
		AssetType:       model.AssetTypeAppliance,
		OSFamily:        "ubiquiti",
		OSVersion:       h.FirmwareVer,
		DiscoverySource: "unifi",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            string(tagsJSON),
		LastSeenAt:      now,
	}
}

func cloudDeviceToAsset(d cloudDevice, now time.Time) model.Asset {
	hostname := d.Name
	if hostname == "" {
		hostname = d.MAC
	}

	tags := map[string]any{
		"mac":      d.MAC,
		"ip":       d.IP,
		"model":    d.Model,
		"firmware": d.Firmware,
		"state":    d.State,
		"type":     d.Type,
		"source":   "unifi_cloud",
	}
	tagsJSON, _ := json.Marshal(tags)

	return model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        hostname,
		AssetType:       model.AssetTypeNetworkDevice,
		OSFamily:        "ubiquiti",
		OSVersion:       d.Firmware,
		DiscoverySource: "unifi",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            string(tagsJSON),
		LastSeenAt:      now,
	}
}

// -------------------------------------------------------------------------
// Local API (session auth to controller on LAN)
// -------------------------------------------------------------------------

func (u *UniFi) discoverLocal(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	endpoint := toString(cfg["endpoint"])
	if endpoint == "" {
		endpoint = os.Getenv("KITE_UNIFI_ENDPOINT")
	}
	username := os.Getenv("KITE_UNIFI_USERNAME")
	password := os.Getenv("KITE_UNIFI_PASSWORD")
	site := toString(cfg["site"])
	if site == "" {
		site = "default"
	}

	if endpoint == "" || username == "" || password == "" {
		return nil, fmt.Errorf(
			"unifi: set KITE_UNIFI_API_KEY (cloud) or " +
				"KITE_UNIFI_ENDPOINT + KITE_UNIFI_USERNAME + " +
				"KITE_UNIFI_PASSWORD (local)")
	}

	// Validate endpoint — UniFi controllers may use HTTP on LAN.
	parsed, err := safenet.ValidateEndpoint(endpoint, safenet.AllowPrivate(), safenet.AllowHTTP())
	if err != nil {
		return nil, fmt.Errorf("unifi: %w", err)
	}
	endpoint = strings.TrimRight(parsed.String(), "/")

	slog.Info("unifi: using local API", slog.String("endpoint", sanitizeLogValue(endpoint)), slog.String("site", sanitizeLogValue(site))) //#nosec G706 -- control chars sanitized; operator-configured values

	client, err := newLocalClient(ctx, endpoint, username, password)
	if err != nil {
		return nil, fmt.Errorf("unifi: login failed: %w", err)
	}
	// Zero password after successful login (defense-in-depth).
	safenet.ZeroString(&password)
	defer client.logout(ctx)

	now := time.Now().UTC()
	var assets []model.Asset

	// Enumerate clients (connected devices).
	clients, err := client.listClients(ctx, site)
	if err != nil {
		slog.Warn("unifi: failed to list clients", "error", err)
	} else {
		for _, c := range clients {
			assets = append(assets, clientToAsset(c, now))
		}
	}

	// Enumerate devices (APs, switches, gateways).
	devices, err := client.listDevices(ctx, site)
	if err != nil {
		slog.Warn("unifi: failed to list devices", "error", err)
	} else {
		for _, d := range devices {
			assets = append(assets, deviceToAsset(d, now))
		}
	}

	slog.Info("unifi: local discovery complete", "assets", len(assets)) //#nosec G706 -- integer count, no injection vector
	return assets, nil
}

// -------------------------------------------------------------------------
// Local HTTP client with session auth
// -------------------------------------------------------------------------

type localClient struct {
	http *http.Client
	base *url.URL
}

func newLocalClient(ctx context.Context, endpoint, username, password string) (*localClient, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint URL %q: %w", endpoint, err)
	}

	jar, _ := cookiejar.New(nil)

	tlsCfg, err := safenet.TLSConfig("KITE_UNIFI_INSECURE", "KITE_UNIFI_CA_CERT")
	if err != nil {
		return nil, fmt.Errorf("unifi: %w", err)
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}

	c := &localClient{
		base: parsed,
		http: &http.Client{
			Transport: transport,
			Timeout:   clientTimeout,
			Jar:       jar,
		},
	}

	if err := c.login(ctx, username, password); err != nil {
		return nil, err
	}

	return c, nil
}

// resolveURL safely joins the base endpoint URL with the given path.
// The URL is reconstructed from validated components (scheme, host) to
// prevent SSRF — the base URL was parsed and scheme-checked in
// newLocalClient.
func (c *localClient) resolveURL(path string) string {
	u := url.URL{
		Scheme: c.base.Scheme,
		Host:   c.base.Host,
		Path:   path,
	}
	return u.String()
}

func (c *localClient) login(ctx context.Context, username, password string) error {
	payload, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})

	// Try UDM/UniFi OS endpoint first, fall back to legacy.
	for _, path := range []string{"/api/auth/login", "/api/login"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, //#nosec G704 -- endpoint is operator-configured, scheme-validated in newLocalClient
			c.resolveURL(path), bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.http.Do(req) //#nosec G704
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			slog.Debug("unifi: logged in via " + path)
			return nil
		}
	}

	return fmt.Errorf("login failed — check credentials, endpoint, " +
		"and ensure the account is a local admin (not a UI.com cloud account)")
}

func (c *localClient) logout(ctx context.Context) {
	// Try both logout paths.
	for _, path := range []string{"/api/auth/logout", "/api/logout"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, //#nosec G704 -- endpoint is operator-configured, scheme-validated in newLocalClient
			c.resolveURL(path), nil)
		if err != nil {
			continue
		}
		resp, err := c.http.Do(req) //#nosec G704
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return
		}
	}
}

func (c *localClient) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.resolveURL(path), nil) //#nosec G704 -- endpoint is operator-configured, scheme-validated in newLocalClient
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req) //#nosec G704
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
// Local API types
// -------------------------------------------------------------------------

// apiResponse wraps the standard UniFi JSON envelope.
type apiResponse struct {
	Meta struct {
		RC string `json:"rc"`
	} `json:"meta"`
	Data json.RawMessage `json:"data"`
}

type unifiClientEntry struct {
	Hostname    string `json:"hostname"`
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	OsName      string `json:"os_name"`
	SwMAC       string `json:"sw_mac"`
	ApName      string `json:"ap_name"`
	Dot1xStatus string `json:"dot1x_status"`
	TxBytes     int64  `json:"tx_bytes"`
	RxBytes     int64  `json:"rx_bytes"`
	LastSeen    int64  `json:"last_seen"`
	VLAN        int    `json:"vlan"`
	SwPort      int    `json:"sw_port"`
	SignalDBM   int    `json:"signal"`
	DevCat      int    `json:"dev_cat"`
	DevFamily   int    `json:"dev_family"`
	Channel     int    `json:"channel"`
	IsWired     bool   `json:"is_wired"`
	IsGuest     bool   `json:"is_guest"`
}

type unifiDevice struct {
	Name       string `json:"name"`
	IP         string `json:"ip"`
	MAC        string `json:"mac"`
	Model      string `json:"model"`
	Type       string `json:"type"`
	Version    string `json:"version"`
	UpgradeTo  string `json:"upgrade_to_firmware"`
	Uptime     int64  `json:"uptime"`
	PortCount  int    `json:"num_sta"`
	Adopted    bool   `json:"adopted"`
	Upgradable bool   `json:"upgradable"`
}

// -------------------------------------------------------------------------
// API calls
// -------------------------------------------------------------------------

func (c *localClient) listClients(ctx context.Context, site string) ([]unifiClientEntry, error) {
	safeSite, err := safenet.SanitizePathSegment(site)
	if err != nil {
		return nil, fmt.Errorf("unifi: unsafe site name: %w", err)
	}
	body, err := c.get(ctx, fmt.Sprintf("/api/s/%s/stat/sta", safeSite))
	if err != nil {
		return nil, err
	}
	var resp apiResponse
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse client response: %w", err)
	}
	var clients []unifiClientEntry
	if err = json.Unmarshal(resp.Data, &clients); err != nil {
		return nil, fmt.Errorf("parse clients: %w", err)
	}
	return clients, nil
}

func (c *localClient) listDevices(ctx context.Context, site string) ([]unifiDevice, error) {
	safeSite, err := safenet.SanitizePathSegment(site)
	if err != nil {
		return nil, fmt.Errorf("unifi: unsafe site name: %w", err)
	}
	body, err := c.get(ctx, fmt.Sprintf("/api/s/%s/stat/device", safeSite))
	if err != nil {
		return nil, err
	}
	var resp apiResponse
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse device response: %w", err)
	}
	var devices []unifiDevice
	if err = json.Unmarshal(resp.Data, &devices); err != nil {
		return nil, fmt.Errorf("parse devices: %w", err)
	}
	return devices, nil
}

// -------------------------------------------------------------------------
// Asset mapping
// -------------------------------------------------------------------------

func clientToAsset(c unifiClientEntry, now time.Time) model.Asset {
	assetType := model.AssetTypeWorkstation
	if c.DevCat == 15 {
		assetType = model.AssetTypeIOTDevice
	}

	hostname := c.Hostname
	if hostname == "" {
		hostname = c.MAC
	}

	lastSeen := now
	if c.LastSeen > 0 {
		lastSeen = time.Unix(c.LastSeen, 0).UTC()
	}

	tags := map[string]any{
		"mac":          c.MAC,
		"ip":           c.IP,
		"vlan":         c.VLAN,
		"switch_port":  c.SwPort,
		"switch_mac":   c.SwMAC,
		"ap_name":      c.ApName,
		"signal_dbm":   c.SignalDBM,
		"is_wired":     c.IsWired,
		"is_guest":     c.IsGuest,
		"dev_category": c.DevCat,
		"dev_family":   c.DevFamily,
		"channel":      c.Channel,
		"tx_bytes":     c.TxBytes,
		"rx_bytes":     c.RxBytes,
	}
	if c.Dot1xStatus != "" {
		tags["dot1x_status"] = c.Dot1xStatus
	}

	tagsJSON, _ := json.Marshal(tags)

	return model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        hostname,
		AssetType:       assetType,
		OSFamily:        c.OsName,
		DiscoverySource: "unifi",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            string(tagsJSON),
		LastSeenAt:      lastSeen,
	}
}

func deviceToAsset(d unifiDevice, now time.Time) model.Asset {
	hostname := d.Name
	if hostname == "" {
		hostname = d.MAC
	}

	tags := map[string]any{
		"mac":        d.MAC,
		"ip":         d.IP,
		"model":      d.Model,
		"type":       d.Type,
		"firmware":   d.Version,
		"uptime":     d.Uptime,
		"port_count": d.PortCount,
		"adopted":    d.Adopted,
		"upgradable": d.Upgradable,
	}
	if d.UpgradeTo != "" {
		tags["upgrade_to"] = d.UpgradeTo
	}

	tagsJSON, _ := json.Marshal(tags)

	return model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        hostname,
		AssetType:       model.AssetTypeNetworkDevice,
		OSFamily:        "ubiquiti",
		OSVersion:       d.Version,
		DiscoverySource: "unifi",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            string(tagsJSON),
		LastSeenAt:      now,
	}
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

// sanitizeLogValue replaces control characters to prevent log injection (CWE-117).
func sanitizeLogValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
