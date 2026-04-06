package vps

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

func newMockOVHcloudAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// Verify OVH triple-auth headers are present.
	checkOVHAuth := func(r *http.Request) bool {
		return r.Header.Get("X-Ovh-Application") != "" &&
			r.Header.Get("X-Ovh-Consumer") != "" &&
			r.Header.Get("X-Ovh-Timestamp") != "" &&
			r.Header.Get("X-Ovh-Signature") != ""
	}

	// List dedicated server names.
	mux.HandleFunc("GET /dedicated/server", func(w http.ResponseWriter, r *http.Request) {
		if !checkOVHAuth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]string{"ns1234.ip-1-2-3.eu", "ns5678.ip-4-5-6.eu"})
	})

	// Dedicated server details.
	mux.HandleFunc("GET /dedicated/server/ns1234.ip-1-2-3.eu", func(w http.ResponseWriter, r *http.Request) {
		if !checkOVHAuth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ovhDedicatedServer{
			Name: "ns1234.ip-1-2-3.eu", IP: "1.2.3.4", OS: "debian11_64",
			Reverse: "server1.example.com", Datacenter: "gra3",
			SupportLevel: "std", CommercialRange: "advance", State: "ok",
		})
	})

	mux.HandleFunc("GET /dedicated/server/ns5678.ip-4-5-6.eu", func(w http.ResponseWriter, r *http.Request) {
		if !checkOVHAuth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ovhDedicatedServer{
			Name: "ns5678.ip-4-5-6.eu", IP: "4.5.6.7", OS: "ubuntu2204_64",
			Datacenter: "rbx8", SupportLevel: "premium",
			CommercialRange: "infra", State: "error",
		})
	})

	// List VPS names.
	mux.HandleFunc("GET /vps", func(w http.ResponseWriter, r *http.Request) {
		if !checkOVHAuth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]string{"vps-abc123.vps.ovh.net"})
	})

	// VPS details.
	mux.HandleFunc("GET /vps/vps-abc123.vps.ovh.net", func(w http.ResponseWriter, r *http.Request) {
		if !checkOVHAuth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ovhVPS{
			Name: "vps-abc123.vps.ovh.net", DisplayName: "my-vps",
			Zone: "eu-west-gra", State: "running",
			Model: ovhVPSModel{Name: "vps-value-1-2-40"},
		})
	})

	return httptest.NewServer(mux)
}

func TestOVHcloud_Name(t *testing.T) {
	assert.Equal(t, "ovhcloud", NewOVHcloud().Name())
}

func TestOVHcloud_Discover_Success(t *testing.T) {
	srv := newMockOVHcloudAPI(t)
	defer srv.Close()

	t.Setenv("KITE_OVHCLOUD_APP_KEY", "test-app-key")
	t.Setenv("KITE_OVHCLOUD_APP_SECRET", "test-app-secret")
	t.Setenv("KITE_OVHCLOUD_CONSUMER_KEY", "test-consumer-key")

	o := NewOVHcloud()
	o.baseURL = srv.URL
	assets, err := o.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Len(t, assets, 3, "expected 2 dedicated + 1 VPS")

	// Verify dedicated server with ok state.
	ded1 := findAssetByHostname(assets, "ns1234.ip-1-2-3.eu")
	require.NotNil(t, ded1)
	assert.Equal(t, model.AssetTypeServer, ded1.AssetType)
	assert.Equal(t, "ovhcloud", ded1.DiscoverySource)
	assert.Equal(t, "debian11_64", ded1.OSFamily)
	assert.Equal(t, "gra3", ded1.Environment)

	var ded1Tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(ded1.Tags), &ded1Tags))
	assert.Equal(t, "1.2.3.4", ded1Tags["ip"])
	assert.NotContains(t, ded1Tags, "warning")

	// Verify dedicated server in error state gets warning.
	ded2 := findAssetByHostname(assets, "ns5678.ip-4-5-6.eu")
	require.NotNil(t, ded2)
	var ded2Tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(ded2.Tags), &ded2Tags))
	assert.Contains(t, ded2Tags, "warning")

	// Verify VPS asset.
	vpsAsset := findAssetByHostname(assets, "my-vps")
	require.NotNil(t, vpsAsset)
	assert.Equal(t, model.AssetTypeCloudInstance, vpsAsset.AssetType)
	assert.Equal(t, "eu-west-gra", vpsAsset.Environment)

	var vpsTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(vpsAsset.Tags), &vpsTags))
	assert.Equal(t, "running", vpsTags["status"])
	assert.NotContains(t, vpsTags, "warning")
}

func TestOVHcloud_Discover_MissingCredentials(t *testing.T) {
	t.Setenv("KITE_OVHCLOUD_APP_KEY", "")
	t.Setenv("KITE_OVHCLOUD_APP_SECRET", "")
	t.Setenv("KITE_OVHCLOUD_CONSUMER_KEY", "")

	o := NewOVHcloud()

	_, err := o.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_OVHCLOUD_APP_KEY")

	assets, err := o.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
}
