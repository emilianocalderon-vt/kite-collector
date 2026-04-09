// Package proxmox implements a discovery.Source that enumerates VMs and LXC
// containers from the Proxmox VE REST API using token-based authentication.
// No vendor SDK dependency — raw HTTP + JSON only.
package proxmox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safenet"
)

const clientTimeout = 30 * time.Second

// Proxmox implements discovery.Source for the Proxmox VE API.
type Proxmox struct{}

// New returns a new Proxmox discovery source.
func New() *Proxmox { return &Proxmox{} }

// Name returns the stable identifier for this source.
func (p *Proxmox) Name() string { return "proxmox" }

// Discover enumerates VMs and LXC containers across all Proxmox cluster nodes.
// Credentials are read from KITE_PROXMOX_TOKEN_ID and KITE_PROXMOX_TOKEN_SECRET
// environment variables.
func (p *Proxmox) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	endpoint := toString(cfg["endpoint"])
	if endpoint == "" {
		endpoint = os.Getenv("KITE_PROXMOX_ENDPOINT")
	}
	tokenID := os.Getenv("KITE_PROXMOX_TOKEN_ID")
	tokenSecret := os.Getenv("KITE_PROXMOX_TOKEN_SECRET")

	if endpoint == "" || tokenID == "" || tokenSecret == "" {
		return nil, fmt.Errorf("proxmox: KITE_PROXMOX_ENDPOINT, KITE_PROXMOX_TOKEN_ID, and KITE_PROXMOX_TOKEN_SECRET are required")
	}

	valOpts := []safenet.Option{safenet.AllowPrivate()}
	if safenet.ParseBoolEnv("KITE_PROXMOX_INSECURE") {
		valOpts = append(valOpts, safenet.AllowHTTP())
	}
	if _, err := safenet.ValidateEndpoint(endpoint, valOpts...); err != nil {
		return nil, fmt.Errorf("proxmox: %w", err)
	}

	endpoint = strings.TrimRight(endpoint, "/")

	slog.Info("proxmox: starting discovery", "endpoint", endpoint) //#nosec G706 -- structured slog

	client, err := newPVEClient(endpoint, tokenID, tokenSecret)
	if err != nil {
		return nil, err
	}

	nodes, err := client.listNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("proxmox: list nodes: %w", err)
	}

	now := time.Now().UTC()
	var assets []model.Asset

	for _, node := range nodes {
		// Enumerate QEMU VMs on this node.
		vms, vmErr := client.listVMs(ctx, node.Node)
		if vmErr != nil {
			slog.Warn("proxmox: list VMs failed", "node", node.Node, "error", vmErr)
		} else {
			for _, vm := range vms {
				cfg, snapshots := fetchVMDetails(ctx, client, node.Node, vm.VMID)
				assets = append(assets, vmToAsset(node.Node, vm, cfg, snapshots, now))
			}
		}

		// Enumerate LXC containers on this node.
		lxcs, lxcErr := client.listLXC(ctx, node.Node)
		if lxcErr != nil {
			slog.Warn("proxmox: list LXC failed", "node", node.Node, "error", lxcErr)
		} else {
			for _, lxc := range lxcs {
				assets = append(assets, lxcToAsset(node.Node, lxc, now))
			}
		}
	}

	slog.Info("proxmox: discovery complete", "assets", len(assets)) //#nosec G706 -- structured slog
	return assets, nil
}

func fetchVMDetails(ctx context.Context, client *pveClient, node string, vmid int) (*vmConfig, []snapshot) {
	cfg, err := client.getVMConfig(ctx, node, vmid)
	if err != nil {
		slog.Warn("proxmox: get VM config failed", "node", node, "vmid", vmid, "error", err)
	}
	snaps, err := client.listSnapshots(ctx, node, vmid)
	if err != nil {
		slog.Warn("proxmox: list snapshots failed", "node", node, "vmid", vmid, "error", err)
	}
	return cfg, snaps
}

// -------------------------------------------------------------------------
// HTTP client with PVE API token auth
// -------------------------------------------------------------------------

type pveClient struct {
	http        *http.Client
	base        string
	tokenID     string
	tokenSecret string
}

func newPVEClient(endpoint, tokenID, tokenSecret string) (*pveClient, error) {
	tc, err := safenet.TLSConfig("KITE_PROXMOX_INSECURE", "KITE_PROXMOX_CA_CERT")
	if err != nil {
		return nil, fmt.Errorf("proxmox TLS: %w", err)
	}
	return &pveClient{
		http: &http.Client{
			Timeout: clientTimeout,
			Transport: &http.Transport{
				TLSClientConfig: tc,
			},
		},
		base:        endpoint,
		tokenID:     tokenID,
		tokenSecret: tokenSecret,
	}, nil
}

func (c *pveClient) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil) //#nosec G704 -- URL from user-configured endpoint
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "PVEAPIToken="+c.tokenID+"="+c.tokenSecret)

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

type pveResponse struct {
	Data json.RawMessage `json:"data"`
}

type pveNode struct {
	Node   string `json:"node"`
	Status string `json:"status"`
}

type pveVM struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	VMID   int    `json:"vmid"`
	CPUs   int    `json:"cpus"`
	MaxMem int64  `json:"maxmem"`
	MaxDisk int64 `json:"maxdisk"`
	Uptime int64  `json:"uptime"`
}

type pveLXC struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	VMID   int    `json:"vmid"`
	CPUs   int    `json:"cpus"`
	MaxMem int64  `json:"maxmem"`
	Uptime int64  `json:"uptime"`
}

type vmConfig struct {
	Boot    string `json:"boot"`
	OSType  string `json:"ostype"`
	Cores   int    `json:"cores"`
	Memory  int    `json:"memory"`
	Sockets int    `json:"sockets"`
}

type snapshot struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	SnapTime    int64  `json:"snaptime"`
}

// -------------------------------------------------------------------------
// API calls
// -------------------------------------------------------------------------

func (c *pveClient) listNodes(ctx context.Context) ([]pveNode, error) {
	body, err := c.get(ctx, "/api2/json/nodes")
	if err != nil {
		return nil, err
	}
	var resp pveResponse
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse nodes: %w", err)
	}
	var nodes []pveNode
	if err = json.Unmarshal(resp.Data, &nodes); err != nil {
		return nil, fmt.Errorf("parse nodes data: %w", err)
	}
	return nodes, nil
}

func (c *pveClient) listVMs(ctx context.Context, node string) ([]pveVM, error) {
	safeNode, err := safenet.SanitizePathSegment(node)
	if err != nil {
		return nil, fmt.Errorf("invalid node name: %w", err)
	}
	body, err := c.get(ctx, fmt.Sprintf("/api2/json/nodes/%s/qemu", safeNode))
	if err != nil {
		return nil, err
	}
	var resp pveResponse
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse VMs: %w", err)
	}
	var vms []pveVM
	if err = json.Unmarshal(resp.Data, &vms); err != nil {
		return nil, fmt.Errorf("parse VMs data: %w", err)
	}
	return vms, nil
}

func (c *pveClient) listLXC(ctx context.Context, node string) ([]pveLXC, error) {
	safeNode, err := safenet.SanitizePathSegment(node)
	if err != nil {
		return nil, fmt.Errorf("invalid node name: %w", err)
	}
	body, err := c.get(ctx, fmt.Sprintf("/api2/json/nodes/%s/lxc", safeNode))
	if err != nil {
		return nil, err
	}
	var resp pveResponse
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse LXC: %w", err)
	}
	var lxcs []pveLXC
	if err = json.Unmarshal(resp.Data, &lxcs); err != nil {
		return nil, fmt.Errorf("parse LXC data: %w", err)
	}
	return lxcs, nil
}

func (c *pveClient) getVMConfig(ctx context.Context, node string, vmid int) (*vmConfig, error) {
	safeNode, err := safenet.SanitizePathSegment(node)
	if err != nil {
		return nil, fmt.Errorf("invalid node name: %w", err)
	}
	body, err := c.get(ctx, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/config", safeNode, vmid))
	if err != nil {
		return nil, err
	}
	var resp pveResponse
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse VM config: %w", err)
	}
	var cfg vmConfig
	if err = json.Unmarshal(resp.Data, &cfg); err != nil {
		return nil, fmt.Errorf("parse VM config data: %w", err)
	}
	return &cfg, nil
}

func (c *pveClient) listSnapshots(ctx context.Context, node string, vmid int) ([]snapshot, error) {
	safeNode, err := safenet.SanitizePathSegment(node)
	if err != nil {
		return nil, fmt.Errorf("invalid node name: %w", err)
	}
	body, err := c.get(ctx, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/snapshot", safeNode, vmid))
	if err != nil {
		return nil, err
	}
	var resp pveResponse
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse snapshots: %w", err)
	}
	var snaps []snapshot
	if err = json.Unmarshal(resp.Data, &snaps); err != nil {
		return nil, fmt.Errorf("parse snapshots data: %w", err)
	}
	return snaps, nil
}

// -------------------------------------------------------------------------
// Asset mapping
// -------------------------------------------------------------------------

func vmToAsset(node string, vm pveVM, cfg *vmConfig, snaps []snapshot, now time.Time) model.Asset {
	hostname := vm.Name
	if hostname == "" {
		hostname = fmt.Sprintf("qemu-%d", vm.VMID)
	}

	tags := map[string]any{
		"node":       node,
		"vmid":       vm.VMID,
		"status":     vm.Status,
		"cpus":       vm.CPUs,
		"max_mem_mb":  vm.MaxMem / (1024 * 1024),
		"max_disk_mb": vm.MaxDisk / (1024 * 1024),
		"uptime":     vm.Uptime,
	}

	if cfg != nil {
		tags["cores"] = cfg.Cores
		tags["memory_mb"] = cfg.Memory
		tags["sockets"] = cfg.Sockets
		tags["os_type"] = cfg.OSType
	}

	if len(snaps) > 0 {
		tags["snapshot_count"] = len(snaps)
		latest := latestSnapshot(snaps)
		if latest != nil && latest.SnapTime > 0 {
			snapAge := now.Sub(time.Unix(latest.SnapTime, 0))
			tags["latest_snapshot_age_hours"] = int(snapAge.Hours())
		}
	}

	tagsJSON, _ := json.Marshal(tags)

	osFamily := ""
	if cfg != nil && cfg.OSType != "" {
		osFamily = cfg.OSType
	}

	return model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        hostname,
		AssetType:       model.AssetTypeVirtualMachine,
		OSFamily:        osFamily,
		DiscoverySource: "proxmox",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            string(tagsJSON),
		LastSeenAt:      now,
	}
}

func lxcToAsset(node string, lxc pveLXC, now time.Time) model.Asset {
	hostname := lxc.Name
	if hostname == "" {
		hostname = fmt.Sprintf("lxc-%d", lxc.VMID)
	}

	tags := map[string]any{
		"node":       node,
		"vmid":       lxc.VMID,
		"status":     lxc.Status,
		"cpus":       lxc.CPUs,
		"max_mem_mb": lxc.MaxMem / (1024 * 1024),
		"uptime":     lxc.Uptime,
	}

	tagsJSON, _ := json.Marshal(tags)

	return model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        hostname,
		AssetType:       model.AssetTypeContainer,
		OSFamily:        "linux",
		DiscoverySource: "proxmox",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            string(tagsJSON),
		LastSeenAt:      now,
	}
}

func latestSnapshot(snaps []snapshot) *snapshot {
	if len(snaps) == 0 {
		return nil
	}
	latest := &snaps[0]
	for i := range snaps {
		if snaps[i].SnapTime > latest.SnapTime {
			latest = &snaps[i]
		}
	}
	return latest
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
