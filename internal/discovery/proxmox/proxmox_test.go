package proxmox

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
// Mock Proxmox API server
// -------------------------------------------------------------------------

func newMockPVEAPI(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/api2/json/nodes", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resp := pveResponse{}
		nodes := []pveNode{
			{Node: "pve1", Status: "online"},
		}
		data, _ := json.Marshal(nodes)
		resp.Data = data
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api2/json/nodes/pve1/qemu", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resp := pveResponse{}
		vms := []pveVM{
			{Name: "web-server", Status: "running", VMID: 100, CPUs: 4, MaxMem: 8589934592, MaxDisk: 107374182400, Uptime: 86400},
			{Name: "db-server", Status: "stopped", VMID: 101, CPUs: 8, MaxMem: 17179869184, MaxDisk: 214748364800},
		}
		data, _ := json.Marshal(vms)
		resp.Data = data
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api2/json/nodes/pve1/lxc", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resp := pveResponse{}
		lxcs := []pveLXC{
			{Name: "dns-resolver", Status: "running", VMID: 200, CPUs: 2, MaxMem: 2147483648, Uptime: 172800},
		}
		data, _ := json.Marshal(lxcs)
		resp.Data = data
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api2/json/nodes/pve1/qemu/100/config", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resp := pveResponse{}
		cfg := vmConfig{Cores: 4, Memory: 8192, Sockets: 1, Boot: "cdn", OSType: "l26"}
		data, _ := json.Marshal(cfg)
		resp.Data = data
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api2/json/nodes/pve1/qemu/100/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resp := pveResponse{}
		snaps := []snapshot{
			{Name: "before-upgrade", Description: "pre-upgrade checkpoint", SnapTime: 1700000000},
		}
		data, _ := json.Marshal(snaps)
		resp.Data = data
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api2/json/nodes/pve1/qemu/101/config", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resp := pveResponse{}
		cfg := vmConfig{Cores: 8, Memory: 16384, Sockets: 2, OSType: "win11"}
		data, _ := json.Marshal(cfg)
		resp.Data = data
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api2/json/nodes/pve1/qemu/101/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		resp := pveResponse{}
		resp.Data = json.RawMessage("[]")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	return httptest.NewServer(mux)
}

func checkAuth(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	return auth == "PVEAPIToken=test@pam!kite=secret-uuid"
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

func TestProxmox_Name(t *testing.T) {
	p := New()
	assert.Equal(t, "proxmox", p.Name())
}

func TestProxmox_Discover_Success(t *testing.T) {
	srv := newMockPVEAPI(t)
	defer srv.Close()

	t.Setenv("KITE_PROXMOX_ENDPOINT", srv.URL)
	t.Setenv("KITE_PROXMOX_TOKEN_ID", "test@pam!kite")
	t.Setenv("KITE_PROXMOX_TOKEN_SECRET", "secret-uuid")
	t.Setenv("KITE_PROXMOX_INSECURE", "true")

	p := New()
	assets, err := p.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Len(t, assets, 3, "2 VMs + 1 LXC")

	// Verify VM asset.
	web := findAsset(assets, "web-server")
	require.NotNil(t, web)
	assert.Equal(t, model.AssetTypeVirtualMachine, web.AssetType)
	assert.Equal(t, "proxmox", web.DiscoverySource)
	assert.Equal(t, "l26", web.OSFamily)

	var webTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(web.Tags), &webTags))
	assert.Equal(t, "pve1", webTags["node"])
	assert.Equal(t, float64(100), webTags["vmid"])
	assert.Equal(t, float64(4), webTags["cores"])
	assert.Equal(t, float64(8192), webTags["memory_mb"])
	assert.Equal(t, float64(1), webTags["snapshot_count"])
	assert.Contains(t, webTags, "latest_snapshot_age_hours")

	// Verify LXC asset.
	dns := findAsset(assets, "dns-resolver")
	require.NotNil(t, dns)
	assert.Equal(t, model.AssetTypeContainer, dns.AssetType)
	assert.Equal(t, "linux", dns.OSFamily)

	var dnsTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(dns.Tags), &dnsTags))
	assert.Equal(t, float64(200), dnsTags["vmid"])
}

func TestProxmox_Discover_MissingCredentials(t *testing.T) {
	t.Setenv("KITE_PROXMOX_ENDPOINT", "")
	t.Setenv("KITE_PROXMOX_TOKEN_ID", "")
	t.Setenv("KITE_PROXMOX_TOKEN_SECRET", "")

	p := New()
	_, err := p.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestProxmox_Discover_AuthFailure(t *testing.T) {
	srv := newMockPVEAPI(t)
	defer srv.Close()

	t.Setenv("KITE_PROXMOX_ENDPOINT", srv.URL)
	t.Setenv("KITE_PROXMOX_TOKEN_ID", "wrong")
	t.Setenv("KITE_PROXMOX_TOKEN_SECRET", "wrong")
	t.Setenv("KITE_PROXMOX_INSECURE", "true")

	p := New()
	_, err := p.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list nodes")
}

func TestLatestSnapshot(t *testing.T) {
	snaps := []snapshot{
		{Name: "old", SnapTime: 1000},
		{Name: "new", SnapTime: 3000},
		{Name: "mid", SnapTime: 2000},
	}
	latest := latestSnapshot(snaps)
	assert.Equal(t, "new", latest.Name)

	assert.Nil(t, latestSnapshot(nil))
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
