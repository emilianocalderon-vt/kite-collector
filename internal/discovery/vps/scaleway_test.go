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

func newMockScalewayAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /instance/v1/zones/fr-par-1/servers", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-Token") != "test-scaleway-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		_ = json.NewEncoder(w).Encode(scalewayServersResponse{
			Servers: []scalewayServer{
				{
					ID: "scw-001", Name: "web-scw", State: "running",
					CommercialType: "DEV1-S",
					Image:          &scalewayImage{Name: "Ubuntu 22.04"},
					PublicIPs:      []scalewayIP{{Address: "51.15.0.1"}},
					Tags:           []string{"web", "production"},
					CreationDate:   "2024-02-10T10:00:00+00:00",
				},
				{
					ID: "scw-002", Name: "db-scw", State: "stopped",
					CommercialType: "DEV1-M",
					PublicIPs:      []scalewayIP{{Address: "51.15.0.2"}},
					CreationDate:   "2024-04-01T12:00:00+00:00",
				},
			},
		})
	})

	return httptest.NewServer(mux)
}

func TestScaleway_Name(t *testing.T) {
	assert.Equal(t, "scaleway", NewScaleway().Name())
}

func TestScaleway_Discover_Success(t *testing.T) {
	srv := newMockScalewayAPI(t)
	defer srv.Close()

	t.Setenv("KITE_SCALEWAY_SECRET_KEY", "test-scaleway-token")
	t.Setenv("KITE_SCALEWAY_ZONE", "fr-par-1")

	s := NewScaleway()
	s.baseURL = srv.URL
	assets, err := s.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Len(t, assets, 2)

	web := findAssetByHostname(assets, "web-scw")
	require.NotNil(t, web)
	assert.Equal(t, model.AssetTypeCloudInstance, web.AssetType)
	assert.Equal(t, "scaleway", web.DiscoverySource)
	assert.Equal(t, "Ubuntu 22.04", web.OSFamily)
	assert.Equal(t, "fr-par-1", web.Environment)

	var webTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(web.Tags), &webTags))
	assert.Equal(t, "51.15.0.1", webTags["ip"])
	assert.NotContains(t, webTags, "warning")

	// Stopped server gets warning.
	db := findAssetByHostname(assets, "db-scw")
	require.NotNil(t, db)
	var dbTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(db.Tags), &dbTags))
	assert.Contains(t, dbTags, "warning")
}

func TestScaleway_Discover_MissingToken(t *testing.T) {
	t.Setenv("KITE_SCALEWAY_SECRET_KEY", "")

	s := NewScaleway()

	_, err := s.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_SCALEWAY_SECRET_KEY")

	assets, err := s.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestScaleway_Discover_AuthFailure(t *testing.T) {
	srv := newMockScalewayAPI(t)
	defer srv.Close()

	t.Setenv("KITE_SCALEWAY_SECRET_KEY", "wrong-token")
	t.Setenv("KITE_SCALEWAY_ZONE", "fr-par-1")

	s := NewScaleway()
	s.baseURL = srv.URL
	_, err := s.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")
}
