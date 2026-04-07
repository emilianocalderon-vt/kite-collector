package cmdb

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

func newMockNetBoxAPI(t *testing.T) *httptest.Server {
	t.Helper()

	var srv *httptest.Server
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/dcim/devices/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token nb-test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		page := r.URL.Query().Get("offset")
		w.Header().Set("Content-Type", "application/json")

		if page == "" || page == "0" {
			next := srv.URL + "/api/dcim/devices/?limit=1000&offset=1000"
			_ = json.NewEncoder(w).Encode(map[string]any{
				"count": 3,
				"next":  next,
				"results": []map[string]any{
					{
						"name":        "core-sw-01",
						"device_role": map[string]any{"name": "Switch", "slug": "switch"},
						"platform":    map[string]any{"name": "Juniper JunOS", "slug": "junos"},
						"site":        map[string]any{"name": "DC-East", "slug": "dc-east"},
						"tenant":      map[string]any{"name": "Engineering", "slug": "engineering"},
						"status":      map[string]any{"value": "active", "label": "Active"},
					},
					{
						"name":        "web-srv-01",
						"device_role": map[string]any{"name": "Server", "slug": "server"},
						"platform":    map[string]any{"name": "Ubuntu Linux", "slug": "ubuntu"},
						"site":        map[string]any{"name": "DC-East", "slug": "dc-east"},
						"tenant":      nil,
						"status":      map[string]any{"value": "active", "label": "Active"},
					},
				},
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"count":   3,
				"next":    nil,
				"results": []map[string]any{
					{
						"name":        "fw-01",
						"device_role": map[string]any{"name": "Firewall", "slug": "firewall"},
						"site":        map[string]any{"name": "DC-West", "slug": "dc-west"},
						"status":      map[string]any{"value": "active", "label": "Active"},
					},
				},
			})
		}
	})

	srv = httptest.NewServer(mux)
	return srv
}

func TestNetBox_Name(t *testing.T) {
	assert.Equal(t, "netbox", NewNetBox().Name())
}

func TestNetBox_Discover_Success(t *testing.T) {
	srv := newMockNetBoxAPI(t)
	defer srv.Close()

	n := NewNetBox()
	cfg := map[string]any{
		"api_url": srv.URL,
		"token":   "nb-test-token",
	}

	assets, err := n.Discover(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, assets, 3)

	// Switch device.
	sw := findAssetByHostname(assets, "core-sw-01")
	require.NotNil(t, sw)
	assert.Equal(t, model.AssetTypeNetworkDevice, sw.AssetType)
	assert.Equal(t, "junos", sw.OSFamily)
	assert.Equal(t, "DC-East", sw.Environment) // site → Environment
	assert.Equal(t, "Engineering", sw.Owner)    // tenant → Owner
	assert.Equal(t, "netbox", sw.DiscoverySource)
	assert.Equal(t, model.AuthorizationAuthorized, sw.IsAuthorized)
	assert.Equal(t, model.ManagedUnknown, sw.IsManaged)
	assert.NotEmpty(t, sw.NaturalKey)

	// Server device.
	webSrv := findAssetByHostname(assets, "web-srv-01")
	require.NotNil(t, webSrv)
	assert.Equal(t, model.AssetTypeServer, webSrv.AssetType)
	assert.Equal(t, "linux", webSrv.OSFamily)
	assert.Empty(t, webSrv.Owner) // no tenant

	// Firewall from page 2.
	fw := findAssetByHostname(assets, "fw-01")
	require.NotNil(t, fw)
	assert.Equal(t, model.AssetTypeNetworkDevice, fw.AssetType)
	assert.Equal(t, "DC-West", fw.Environment)
}

func TestNetBox_Discover_MissingCredentials(t *testing.T) {
	n := NewNetBox()

	assets, err := n.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestNetBox_Discover_AuthFailure(t *testing.T) {
	srv := newMockNetBoxAPI(t)
	defer srv.Close()

	n := NewNetBox()
	cfg := map[string]any{
		"api_url": srv.URL,
		"token":   "wrong-token",
	}

	// Auth failure → returns empty (not an error).
	assets, err := n.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Empty(t, assets)
}

func TestNetBox_Discover_MalformedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"count":   1,
			"next":    nil,
			"results": []map[string]any{{"not_a_device": true}},
		})
	}))
	defer srv.Close()

	n := NewNetBox()
	cfg := map[string]any{
		"api_url": srv.URL,
		"token":   "tok",
	}

	// Malformed entries parse with empty fields.
	assets, err := n.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Len(t, assets, 1)
}

func TestClassifyNetBoxDevice(t *testing.T) {
	assert.Equal(t, model.AssetTypeServer, classifyNetBoxDevice("server"))
	assert.Equal(t, model.AssetTypeNetworkDevice, classifyNetBoxDevice("switch"))
	assert.Equal(t, model.AssetTypeNetworkDevice, classifyNetBoxDevice("router"))
	assert.Equal(t, model.AssetTypeNetworkDevice, classifyNetBoxDevice("firewall"))
	assert.Equal(t, model.AssetTypeWorkstation, classifyNetBoxDevice("workstation"))
	assert.Equal(t, model.AssetTypeAppliance, classifyNetBoxDevice("appliance"))
	assert.Equal(t, model.AssetTypeServer, classifyNetBoxDevice("unknown-role"))
}

func TestDeriveNetBoxOSFamily(t *testing.T) {
	assert.Equal(t, "windows", deriveNetBoxOSFamily("Windows Server"))
	assert.Equal(t, "linux", deriveNetBoxOSFamily("Ubuntu Linux"))
	assert.Equal(t, "junos", deriveNetBoxOSFamily("Juniper JunOS"))
	assert.Equal(t, "ios", deriveNetBoxOSFamily("Cisco IOS"))
	assert.Equal(t, "eos", deriveNetBoxOSFamily("Arista EOS"))
	assert.Equal(t, "darwin", deriveNetBoxOSFamily("macOS"))
	assert.Equal(t, "freebsd", deriveNetBoxOSFamily("FreeBSD"))
}

// findAssetByHostname returns the first asset matching hostname, or nil.
func findAssetByHostname(assets []model.Asset, hostname string) *model.Asset {
	for i := range assets {
		if assets[i].Hostname == hostname {
			return &assets[i]
		}
	}
	return nil
}
