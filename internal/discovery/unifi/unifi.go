// Package unifi implements a discovery.Source that enumerates clients and
// network devices from a Ubiquiti UniFi Controller REST API.  Communication
// uses session-based authentication — no vendor SDK dependency.
package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const clientTimeout = 30 * time.Second

// UniFi implements discovery.Source for the UniFi Controller API.
type UniFi struct{}

// New returns a new UniFi discovery source.
func New() *UniFi { return &UniFi{} }

// Name returns the stable identifier for this source.
func (u *UniFi) Name() string { return "unifi" }

// Discover enumerates clients and devices from the UniFi Controller.
// Credentials are read from KITE_UNIFI_USERNAME and KITE_UNIFI_PASSWORD
// environment variables.  The endpoint and site can be set via cfg or
// KITE_UNIFI_ENDPOINT env.
func (u *UniFi) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
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
		return nil, fmt.Errorf("unifi: KITE_UNIFI_ENDPOINT, KITE_UNIFI_USERNAME, and KITE_UNIFI_PASSWORD are required")
	}

	endpoint = strings.TrimRight(endpoint, "/")

	slog.Info("unifi: starting discovery", "endpoint", endpoint, "site", site) //#nosec G706 -- structured slog key-value

	client, err := newUniFiClient(ctx, endpoint, username, password)
	if err != nil {
		return nil, fmt.Errorf("unifi: login failed: %w", err)
	}
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

	slog.Info("unifi: discovery complete", "assets", len(assets)) //#nosec G706 -- structured slog
	return assets, nil
}

// -------------------------------------------------------------------------
// HTTP client with session auth
// -------------------------------------------------------------------------

type unifiClient struct {
	http *http.Client
	base string
}

func newUniFiClient(ctx context.Context, endpoint, username, password string) (*unifiClient, error) {
	jar, _ := cookiejar.New(nil)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	// Accept self-signed certs if KITE_UNIFI_INSECURE is set.
	if os.Getenv("KITE_UNIFI_INSECURE") == "true" {
		slog.Warn("unifi: TLS verification disabled — not recommended for production")
		transport.TLSClientConfig.InsecureSkipVerify = true //#nosec G402 -- user-opted insecure mode
	}

	c := &unifiClient{
		base: endpoint,
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

func (c *unifiClient) login(ctx context.Context, username, password string) error {
	payload, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, //#nosec G704 -- URL from user-configured endpoint
		c.base+"/api/login", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req) //#nosec G704 -- intentional request to user-configured endpoint
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login returned HTTP %d — check credentials and endpoint", resp.StatusCode)
	}

	return nil
}

func (c *unifiClient) logout(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, //#nosec G704 -- logout to user-configured endpoint
		c.base+"/api/logout", nil)
	if err != nil {
		return
	}
	resp, err := c.http.Do(req) //#nosec G704 -- intentional request to user-configured endpoint
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func (c *unifiClient) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil) //#nosec G704 -- URL from user-configured endpoint
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

func (c *unifiClient) listClients(ctx context.Context, site string) ([]unifiClientEntry, error) {
	body, err := c.get(ctx, fmt.Sprintf("/api/s/%s/stat/sta", site))
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

func (c *unifiClient) listDevices(ctx context.Context, site string) ([]unifiDevice, error) {
	body, err := c.get(ctx, fmt.Sprintf("/api/s/%s/stat/device", site))
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
