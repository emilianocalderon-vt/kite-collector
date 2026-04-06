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

func newMockUpCloudAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /server", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "test-user" || pass != "test-pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		_ = json.NewEncoder(w).Encode(upcloudServersResponse{
			Servers: upcloudServerList{
				Server: []upcloudServer{
					{
						UUID: "uc-001", Hostname: "web-uc", State: "started",
						Plan: "1xCPU-2GB", Zone: "fi-hel1", Title: "Web Server",
						IPAddresses: upcloudIPAddresses{
							IPAddress: []upcloudIP{
								{Address: "10.0.0.1", Access: "private", Family: "IPv4"},
								{Address: "94.237.0.1", Access: "public", Family: "IPv4"},
								{Address: "2001:db8::1", Access: "public", Family: "IPv6"},
							},
						},
						Tags: upcloudTags{Tag: []string{"web"}},
					},
					{
						UUID: "uc-002", Hostname: "", State: "stopped",
						Plan: "2xCPU-4GB", Zone: "de-fra1", Title: "DB Server",
						IPAddresses: upcloudIPAddresses{
							IPAddress: []upcloudIP{
								{Address: "94.237.0.2", Access: "public", Family: "IPv4"},
							},
						},
					},
				},
			},
		})
	})

	return httptest.NewServer(mux)
}

func TestUpCloud_Name(t *testing.T) {
	assert.Equal(t, "upcloud", NewUpCloud().Name())
}

func TestUpCloud_Discover_Success(t *testing.T) {
	srv := newMockUpCloudAPI(t)
	defer srv.Close()

	t.Setenv("KITE_UPCLOUD_USERNAME", "test-user")
	t.Setenv("KITE_UPCLOUD_PASSWORD", "test-pass")

	u := NewUpCloud()
	u.baseURL = srv.URL
	assets, err := u.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Len(t, assets, 2)

	// Verify running server with public IPv4 extracted.
	web := findAssetByHostname(assets, "web-uc")
	require.NotNil(t, web)
	assert.Equal(t, model.AssetTypeCloudInstance, web.AssetType)
	assert.Equal(t, "upcloud", web.DiscoverySource)
	assert.Equal(t, "fi-hel1", web.Environment)

	var webTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(web.Tags), &webTags))
	assert.Equal(t, "94.237.0.1", webTags["ip"])
	assert.NotContains(t, webTags, "warning")

	// Verify stopped server: hostname falls back to Title, gets warning.
	db := findAssetByHostname(assets, "DB Server")
	require.NotNil(t, db)
	var dbTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(db.Tags), &dbTags))
	assert.Contains(t, dbTags, "warning")
}

func TestUpCloud_Discover_MissingCredentials(t *testing.T) {
	t.Setenv("KITE_UPCLOUD_USERNAME", "")
	t.Setenv("KITE_UPCLOUD_PASSWORD", "")

	u := NewUpCloud()

	_, err := u.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_UPCLOUD_USERNAME")

	assets, err := u.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestUpCloud_Discover_AuthFailure(t *testing.T) {
	srv := newMockUpCloudAPI(t)
	defer srv.Close()

	t.Setenv("KITE_UPCLOUD_USERNAME", "wrong-user")
	t.Setenv("KITE_UPCLOUD_PASSWORD", "wrong-pass")

	u := NewUpCloud()
	u.baseURL = srv.URL
	_, err := u.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")
}
