package mdm

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

func newMockJamfAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// Computer list endpoint.
	mux.HandleFunc("GET /JSSResource/computers", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"computers": []map[string]any{
				{"id": 1, "name": "mac-pro-1"},
				{"id": 2, "name": "macbook-2"},
			},
		})
	})

	// Computer detail endpoint.
	mux.HandleFunc("GET /JSSResource/computers/id/{id}", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		id := r.PathValue("id")
		w.Header().Set("Content-Type", "application/json")

		switch id {
		case "1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"computer": map[string]any{
					"general":  map[string]any{"name": "mac-pro-1", "serial_number": "C02ABC123", "id": 1},
					"hardware": map[string]any{"os_name": "macOS", "os_version": "14.2", "os_build": "23C64"},
				},
			})
		case "2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"computer": map[string]any{
					"general":  map[string]any{"name": "macbook-2", "serial_number": "C02DEF456", "id": 2},
					"hardware": map[string]any{"os_name": "Mac OS X", "os_version": "13.6", "os_build": "22G120"},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	return httptest.NewServer(mux)
}

func TestJamf_Name(t *testing.T) {
	assert.Equal(t, "jamf", NewJamf().Name())
}

func TestJamf_Discover_Success(t *testing.T) {
	srv := newMockJamfAPI(t)
	defer srv.Close()

	j := NewJamf()
	cfg := map[string]any{
		"api_url":  srv.URL,
		"username": "admin",
		"password": "secret",
	}

	assets, err := j.Discover(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, assets, 2)

	mac1 := findAsset(assets, "mac-pro-1")
	require.NotNil(t, mac1)
	assert.Equal(t, model.AssetTypeWorkstation, mac1.AssetType)
	assert.Equal(t, "darwin", mac1.OSFamily)
	assert.Equal(t, "14.2", mac1.OSVersion)
	assert.Equal(t, "jamf", mac1.DiscoverySource)
	assert.Equal(t, model.ManagedManaged, mac1.IsManaged)
	assert.Equal(t, model.AuthorizationUnknown, mac1.IsAuthorized)
	assert.NotEmpty(t, mac1.NaturalKey)

	mac2 := findAsset(assets, "macbook-2")
	require.NotNil(t, mac2)
	assert.Equal(t, "darwin", mac2.OSFamily)
}

func TestJamf_Discover_MissingCredentials(t *testing.T) {
	j := NewJamf()

	assets, err := j.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestJamf_Discover_AuthFailure(t *testing.T) {
	srv := newMockJamfAPI(t)
	defer srv.Close()

	j := NewJamf()
	cfg := map[string]any{
		"api_url":  srv.URL,
		"username": "admin",
		"password": "wrong",
	}

	// Auth failure returns nil, nil (Jamf returns nil on 401).
	assets, err := j.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestJamf_Discover_DetailFetchFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /JSSResource/computers", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"computers": []map[string]any{
				{"id": 99, "name": "ghost"},
			},
		})
	})
	mux.HandleFunc("GET /JSSResource/computers/id/99", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	j := NewJamf()
	cfg := map[string]any{
		"api_url":  srv.URL,
		"username": "admin",
		"password": "secret",
	}

	// Individual detail failure is skipped, not an overall error.
	assets, err := j.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Empty(t, assets)
}

func TestDeriveJamfOSFamily(t *testing.T) {
	assert.Equal(t, "darwin", deriveJamfOSFamily("macOS"))
	assert.Equal(t, "darwin", deriveJamfOSFamily("Mac OS X"))
	assert.Equal(t, "darwin", deriveJamfOSFamily("OS X"))
	assert.Equal(t, "windows", deriveJamfOSFamily("Windows"))
	assert.Equal(t, "linux", deriveJamfOSFamily("Linux"))
	assert.Equal(t, "darwin", deriveJamfOSFamily("SomethingElse")) // default
}
