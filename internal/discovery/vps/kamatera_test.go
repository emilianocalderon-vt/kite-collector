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

func newMockKamateraAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /service/servers", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("AuthClientId") != "test-client-id" ||
			r.Header.Get("AuthSecret") != "test-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		_ = json.NewEncoder(w).Encode([]kamateraServer{
			{
				Name: "web-kam", ID: "kam-001", Datacenter: "EU",
				Power: "on", CPU: "2B", RAM: 4096,
				IPs: []string{"185.0.0.1", "10.0.0.1"},
			},
			{
				Name: "db-kam", ID: "kam-002", Datacenter: "US",
				Power: "off", CPU: "4B", RAM: 8192,
				IPs: []string{"185.0.0.2"},
			},
		})
	})

	return httptest.NewServer(mux)
}

func TestKamatera_Name(t *testing.T) {
	assert.Equal(t, "kamatera", NewKamatera().Name())
}

func TestKamatera_Discover_Success(t *testing.T) {
	srv := newMockKamateraAPI(t)
	defer srv.Close()

	t.Setenv("KITE_KAMATERA_CLIENT_ID", "test-client-id")
	t.Setenv("KITE_KAMATERA_SECRET", "test-secret")

	k := NewKamatera()
	k.baseURL = srv.URL
	assets, err := k.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Len(t, assets, 2)

	web := findAssetByHostname(assets, "web-kam")
	require.NotNil(t, web)
	assert.Equal(t, model.AssetTypeCloudInstance, web.AssetType)
	assert.Equal(t, "kamatera", web.DiscoverySource)
	assert.Equal(t, "EU", web.Environment)
	assert.NotEmpty(t, web.NaturalKey)

	var webTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(web.Tags), &webTags))
	assert.Equal(t, "185.0.0.1", webTags["ip"])
	assert.NotContains(t, webTags, "warning")

	// Powered-off server gets warning.
	db := findAssetByHostname(assets, "db-kam")
	require.NotNil(t, db)
	var dbTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(db.Tags), &dbTags))
	assert.Equal(t, "off", dbTags["status"])
	assert.Contains(t, dbTags, "warning")
}

func TestKamatera_Discover_MissingCredentials(t *testing.T) {
	t.Setenv("KITE_KAMATERA_CLIENT_ID", "")
	t.Setenv("KITE_KAMATERA_SECRET", "")

	k := NewKamatera()

	_, err := k.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_KAMATERA_CLIENT_ID")

	assets, err := k.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestKamatera_Discover_AuthFailure(t *testing.T) {
	srv := newMockKamateraAPI(t)
	defer srv.Close()

	t.Setenv("KITE_KAMATERA_CLIENT_ID", "wrong-id")
	t.Setenv("KITE_KAMATERA_SECRET", "wrong-secret")

	k := NewKamatera()
	k.baseURL = srv.URL
	_, err := k.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")
}
