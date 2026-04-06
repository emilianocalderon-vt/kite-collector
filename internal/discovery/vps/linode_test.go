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

func newMockLinodeAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /linode/instances", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-linode-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")

		if page == "" || page == "1" {
			last := "2024-06-01T00:00:00"
			_ = json.NewEncoder(w).Encode(linodeInstancesResponse{
				Data: []linodeInstance{
					{
						ID: 1001, Label: "web-linode", Status: "running",
						Image: "linode/ubuntu22.04", Type: "g6-standard-2",
						Region: "us-east", Created: "2024-01-10T08:00:00Z",
						IPv4: []string{"192.0.2.1", "10.0.0.1"},
						Tags: []string{"production"},
						Backups: linodeBackups{
							Enabled:        true,
							LastSuccessful: &last,
						},
					},
					{
						ID: 1002, Label: "db-linode", Status: "offline",
						Image: "linode/debian12", Type: "g6-standard-4",
						Region: "eu-west", Created: "2024-03-15T12:00:00Z",
						IPv4: []string{"192.0.2.2"},
						Backups: linodeBackups{Enabled: false},
					},
				},
				Page: 1, Pages: 2, Results: 3,
			})
		} else {
			_ = json.NewEncoder(w).Encode(linodeInstancesResponse{
				Data: []linodeInstance{
					{
						ID: 1003, Label: "worker-linode", Status: "running",
						Image: "linode/fedora39", Type: "g6-standard-1",
						Region: "ap-south", Created: "2024-05-20T09:00:00Z",
						IPv4: []string{"192.0.2.3"},
						Backups: linodeBackups{Enabled: false},
					},
				},
				Page: 2, Pages: 2, Results: 3,
			})
		}
	})

	return httptest.NewServer(mux)
}

func TestLinode_Name(t *testing.T) {
	assert.Equal(t, "linode", NewLinode().Name())
}

func TestLinode_Discover_Success(t *testing.T) {
	srv := newMockLinodeAPI(t)
	defer srv.Close()

	t.Setenv("KITE_LINODE_TOKEN", "test-linode-token")

	l := NewLinode()
	l.baseURL = srv.URL
	assets, err := l.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Len(t, assets, 3)

	web := findAssetByHostname(assets, "web-linode")
	require.NotNil(t, web)
	assert.Equal(t, model.AssetTypeCloudInstance, web.AssetType)
	assert.Equal(t, "linode", web.DiscoverySource)
	assert.Equal(t, "linode/ubuntu22.04", web.OSFamily)
	assert.Equal(t, "us-east", web.Environment)

	var webTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(web.Tags), &webTags))
	assert.Equal(t, "192.0.2.1", webTags["ip"])
	assert.Equal(t, true, webTags["backups_enabled"])
	assert.NotContains(t, webTags, "warning")

	// Offline instance gets warning.
	db := findAssetByHostname(assets, "db-linode")
	require.NotNil(t, db)
	var dbTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(db.Tags), &dbTags))
	assert.Contains(t, dbTags, "warning")
}

func TestLinode_Discover_MissingToken(t *testing.T) {
	t.Setenv("KITE_LINODE_TOKEN", "")

	l := NewLinode()

	_, err := l.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_LINODE_TOKEN")

	assets, err := l.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestLinode_Discover_AuthFailure(t *testing.T) {
	srv := newMockLinodeAPI(t)
	defer srv.Close()

	t.Setenv("KITE_LINODE_TOKEN", "wrong-token")

	l := NewLinode()
	l.baseURL = srv.URL
	_, err := l.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")
}
