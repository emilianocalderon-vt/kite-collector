package unifi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// -------------------------------------------------------------------------
// Mock UniFi Controller
// -------------------------------------------------------------------------

func newMockUniFiController(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&creds)
		if creds.Username != "admin" || creds.Password != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "unifises", Value: "test-session"})
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/api/s/default/stat/sta", func(w http.ResponseWriter, _ *http.Request) {
		resp := apiResponse{}
		clients := []unifiClientEntry{
			{
				Hostname:  "laptop-01",
				IP:        "192.168.1.50",
				MAC:       "aa:bb:cc:dd:ee:01",
				OsName:    "Windows",
				VLAN:      10,
				SwPort:    17,
				ApName:    "AP-LR-Office",
				SignalDBM: -62,
				IsWired:   false,
				DevCat:    1,
				Channel:   36,
				TxBytes:   1234567890,
				RxBytes:   987654321,
				LastSeen:  1700000000,
			},
			{
				Hostname: "iot-sensor",
				IP:       "192.168.1.100",
				MAC:      "aa:bb:cc:dd:ee:02",
				VLAN:     20,
				IsWired:  true,
				DevCat:   15,
				LastSeen: 1700000100,
			},
		}
		data, _ := json.Marshal(clients)
		resp.Data = data
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/s/default/stat/device", func(w http.ResponseWriter, _ *http.Request) {
		resp := apiResponse{}
		devices := []unifiDevice{
			{
				Name:       "US-24-Office",
				IP:         "192.168.1.2",
				MAC:        "ff:ee:dd:cc:bb:01",
				Model:      "US-24-250W",
				Type:       "usw",
				Version:    "6.6.65",
				Uptime:     8640000,
				PortCount:  24,
				Adopted:    true,
				Upgradable: true,
				UpgradeTo:  "6.6.71",
			},
		}
		data, _ := json.Marshal(devices)
		resp.Data = data
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	return httptest.NewServer(mux)
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

func TestUniFi_Name(t *testing.T) {
	u := New()
	assert.Equal(t, "unifi", u.Name())
}

func TestUniFi_Discover_Success(t *testing.T) {
	srv := newMockUniFiController(t)
	defer srv.Close()

	t.Setenv("KITE_UNIFI_ENDPOINT", srv.URL)
	t.Setenv("KITE_UNIFI_USERNAME", "admin")
	t.Setenv("KITE_UNIFI_PASSWORD", "secret")

	u := New()
	cfg := map[string]any{"site": "default"}

	assets, err := u.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Len(t, assets, 3, "2 clients + 1 device")

	// Verify workstation client.
	laptop := findAsset(assets, "laptop-01")
	require.NotNil(t, laptop)
	assert.Equal(t, model.AssetTypeWorkstation, laptop.AssetType)
	assert.Equal(t, "Windows", laptop.OSFamily)
	assert.Equal(t, "unifi", laptop.DiscoverySource)

	var laptopTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(laptop.Tags), &laptopTags))
	assert.Equal(t, float64(10), laptopTags["vlan"])
	assert.Equal(t, float64(17), laptopTags["switch_port"])
	assert.Equal(t, "AP-LR-Office", laptopTags["ap_name"])
	assert.Equal(t, float64(-62), laptopTags["signal_dbm"])
	assert.Equal(t, false, laptopTags["is_wired"])

	// Verify IoT device.
	iot := findAsset(assets, "iot-sensor")
	require.NotNil(t, iot)
	assert.Equal(t, model.AssetTypeIOTDevice, iot.AssetType)

	// Verify network device.
	sw := findAsset(assets, "US-24-Office")
	require.NotNil(t, sw)
	assert.Equal(t, model.AssetTypeNetworkDevice, sw.AssetType)
	assert.Equal(t, "6.6.65", sw.OSVersion)

	var swTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(sw.Tags), &swTags))
	assert.Equal(t, "US-24-250W", swTags["model"])
	assert.Equal(t, true, swTags["adopted"])
	assert.Equal(t, true, swTags["upgradable"])
	assert.Equal(t, "6.6.71", swTags["upgrade_to"])
}

func TestUniFi_Discover_MissingCredentials(t *testing.T) {
	t.Setenv("KITE_UNIFI_ENDPOINT", "")
	t.Setenv("KITE_UNIFI_USERNAME", "")
	t.Setenv("KITE_UNIFI_PASSWORD", "")

	u := New()
	_, err := u.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestUniFi_Discover_LoginFailure(t *testing.T) {
	srv := newMockUniFiController(t)
	defer srv.Close()

	t.Setenv("KITE_UNIFI_ENDPOINT", srv.URL)
	t.Setenv("KITE_UNIFI_USERNAME", "admin")
	t.Setenv("KITE_UNIFI_PASSWORD", "wrong")

	u := New()
	_, err := u.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "login failed")
}

func TestUniFi_ClientToAsset_UUIDv7(t *testing.T) {
	srv := newMockUniFiController(t)
	defer srv.Close()

	t.Setenv("KITE_UNIFI_ENDPOINT", srv.URL)
	t.Setenv("KITE_UNIFI_USERNAME", "admin")
	t.Setenv("KITE_UNIFI_PASSWORD", "secret")

	u := New()
	assets, err := u.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)

	for _, a := range assets {
		assert.NotEmpty(t, a.ID, "asset must have a UUID")
	}
}

func TestUniFi_ClientFallbackHostname(t *testing.T) {
	srv := newMockUniFiController(t)
	defer srv.Close()

	t.Setenv("KITE_UNIFI_ENDPOINT", srv.URL)
	t.Setenv("KITE_UNIFI_USERNAME", "admin")
	t.Setenv("KITE_UNIFI_PASSWORD", "secret")

	// The mock server returns clients with hostnames, but we test the
	// fallback logic directly through the mapping function.
	entry := unifiClientEntry{MAC: "aa:bb:cc:dd:ee:ff"}
	asset := clientToAsset(entry, fixedTime())
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", asset.Hostname, "should fall back to MAC when hostname is empty")
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

func fixedTime() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}
