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

func newMockHostingerAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/vps/v1/virtual-machines", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-hostinger-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")

		if page == "" || page == "1" {
			_ = json.NewEncoder(w).Encode(hostingerVMsResponse{
				NextPage: "page2",
				Data: []hostingerVM{
					{
						ID: 1, Hostname: "web-host-1", State: "running",
						IPAddress: "10.0.0.1", OS: "Ubuntu 22.04",
						Datacenter: "us-east-1", VCPU: 4, RAM: 8192, Disk: 80,
					},
					{
						ID: 2, Hostname: "db-host-1", State: "stopped",
						IPAddress: "10.0.0.2", OS: "Debian 12",
						Datacenter: "eu-west-1", VCPU: 2, RAM: 4096, Disk: 40,
					},
				},
			})
		} else {
			_ = json.NewEncoder(w).Encode(hostingerVMsResponse{
				Data: []hostingerVM{
					{
						ID: 3, Hostname: "worker-host-1", State: "running",
						IPAddress: "10.0.0.3", OS: "CentOS 9",
						Datacenter: "ap-south-1", VCPU: 1, RAM: 2048, Disk: 20,
					},
				},
			})
		}
	})

	return httptest.NewServer(mux)
}

func TestHostinger_Name(t *testing.T) {
	assert.Equal(t, "hostinger", NewHostinger().Name())
}

func TestHostinger_Discover_Success(t *testing.T) {
	srv := newMockHostingerAPI(t)
	defer srv.Close()

	t.Setenv("KITE_HOSTINGER_TOKEN", "test-hostinger-token")

	h := NewHostinger()
	h.baseURL = srv.URL
	assets, err := h.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Len(t, assets, 3)

	web := findAssetByHostname(assets, "web-host-1")
	require.NotNil(t, web)
	assert.Equal(t, model.AssetTypeCloudInstance, web.AssetType)
	assert.Equal(t, "hostinger", web.DiscoverySource)
	assert.Equal(t, "Ubuntu 22.04", web.OSFamily)
	assert.Equal(t, "us-east-1", web.Environment)
	assert.NotEmpty(t, web.NaturalKey)

	var webTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(web.Tags), &webTags))
	assert.Equal(t, "10.0.0.1", webTags["ip"])
	assert.NotContains(t, webTags, "warning")

	// Stopped VM gets warning.
	db := findAssetByHostname(assets, "db-host-1")
	require.NotNil(t, db)
	var dbTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(db.Tags), &dbTags))
	assert.Contains(t, dbTags, "warning")
}

func TestHostinger_Discover_MissingToken(t *testing.T) {
	t.Setenv("KITE_HOSTINGER_TOKEN", "")

	h := NewHostinger()

	_, err := h.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_HOSTINGER_TOKEN")

	assets, err := h.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestHostinger_Discover_AuthFailure(t *testing.T) {
	srv := newMockHostingerAPI(t)
	defer srv.Close()

	t.Setenv("KITE_HOSTINGER_TOKEN", "wrong-token")

	h := NewHostinger()
	h.baseURL = srv.URL
	_, err := h.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")
}
