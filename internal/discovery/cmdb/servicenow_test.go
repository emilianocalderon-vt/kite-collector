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

func newMockServiceNowAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/now/table/{table}", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "snow-user" || pass != "snow-pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		offset := r.URL.Query().Get("sysparm_offset")
		w.Header().Set("Content-Type", "application/json")

		if offset == "" || offset == "0" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": []map[string]string{
					{
						"sys_id":             "abc123",
						"name":               "prod-db-01",
						"os":                 "Red Hat Enterprise Linux",
						"os_version":         "8.6",
						"ip_address":         "10.0.1.50",
						"asset_tag":          "ASSET-1001",
						"operational_status": "1",
					},
					{
						"sys_id":             "def456",
						"name":               "prod-web-01",
						"os":                 "Windows Server",
						"os_version":         "2022",
						"ip_address":         "10.0.1.51",
						"asset_tag":          "ASSET-1002",
						"operational_status": "1",
					},
				},
			})
		} else {
			// Empty second page — signals end of pagination.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": []map[string]string{},
			})
		}
	})

	return httptest.NewServer(mux)
}

// newMockServiceNowPaginatedAPI returns a server with a full first page
// to exercise the hasMore logic.
func newMockServiceNowPaginatedAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/now/table/{table}", func(w http.ResponseWriter, r *http.Request) {
		offset := r.URL.Query().Get("sysparm_offset")
		w.Header().Set("Content-Type", "application/json")

		if offset == "" || offset == "0" {
			// Return exactly serviceNowPageSize (1000) items to trigger next page.
			items := make([]map[string]string, serviceNowPageSize)
			for i := range items {
				items[i] = map[string]string{
					"sys_id": "id-" + string(rune('A'+i%26)),
					"name":   "ci-" + string(rune('A'+i%26)),
					"os":     "Linux",
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"result": items})
		} else {
			// Second page: one more item.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": []map[string]string{
					{"sys_id": "last", "name": "ci-last", "os": "Windows"},
				},
			})
		}
	})

	return httptest.NewServer(mux)
}

func TestServiceNow_Name(t *testing.T) {
	assert.Equal(t, "servicenow", NewServiceNow().Name())
}

func TestServiceNow_Discover_Success(t *testing.T) {
	srv := newMockServiceNowAPI(t)
	defer srv.Close()

	s := NewServiceNow()
	cfg := map[string]any{
		"instance_url": srv.URL,
		"username":     "snow-user",
		"password":     "snow-pass",
		"table":        "cmdb_ci_server",
	}

	assets, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, assets, 2)

	db := findAssetByHostname(assets, "prod-db-01")
	require.NotNil(t, db)
	assert.Equal(t, model.AssetTypeServer, db.AssetType)
	assert.Equal(t, "linux", db.OSFamily)
	assert.Equal(t, "8.6", db.OSVersion)
	assert.Equal(t, "servicenow", db.DiscoverySource)
	assert.Equal(t, model.AuthorizationAuthorized, db.IsAuthorized)
	assert.Equal(t, model.ManagedUnknown, db.IsManaged)
	assert.NotEmpty(t, db.NaturalKey)

	web := findAssetByHostname(assets, "prod-web-01")
	require.NotNil(t, web)
	assert.Equal(t, "windows", web.OSFamily)
}

func TestServiceNow_Discover_DefaultTable(t *testing.T) {
	srv := newMockServiceNowAPI(t)
	defer srv.Close()

	s := NewServiceNow()
	cfg := map[string]any{
		"instance_url": srv.URL,
		"username":     "snow-user",
		"password":     "snow-pass",
		// table omitted — should default to cmdb_ci_server.
	}

	assets, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Len(t, assets, 2)
}

func TestServiceNow_Discover_MissingCredentials(t *testing.T) {
	s := NewServiceNow()

	assets, err := s.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestServiceNow_Discover_AuthFailure(t *testing.T) {
	srv := newMockServiceNowAPI(t)
	defer srv.Close()

	s := NewServiceNow()
	cfg := map[string]any{
		"instance_url": srv.URL,
		"username":     "snow-user",
		"password":     "wrong",
	}

	// Auth failure → returns nil (graceful).
	assets, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestServiceNow_Discover_Pagination(t *testing.T) {
	srv := newMockServiceNowPaginatedAPI(t)
	defer srv.Close()

	s := NewServiceNow()
	cfg := map[string]any{
		"instance_url": srv.URL,
		"username":     "u",
		"password":     "p",
	}

	assets, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Len(t, assets, serviceNowPageSize+1)
}

func TestServiceNow_Discover_MalformedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":[{"not":"a ci"}]}`))
	}))
	defer srv.Close()

	s := NewServiceNow()
	cfg := map[string]any{
		"instance_url": srv.URL,
		"username":     "u",
		"password":     "p",
	}

	// Malformed entries parse with empty fields.
	assets, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Len(t, assets, 1)
}

func TestDeriveServiceNowOSFamily(t *testing.T) {
	assert.Equal(t, "windows", deriveServiceNowOSFamily("Windows Server"))
	assert.Equal(t, "linux", deriveServiceNowOSFamily("Red Hat Enterprise Linux"))
	assert.Equal(t, "linux", deriveServiceNowOSFamily("Ubuntu"))
	assert.Equal(t, "darwin", deriveServiceNowOSFamily("macOS"))
	assert.Equal(t, "aix", deriveServiceNowOSFamily("AIX"))
	assert.Equal(t, "solaris", deriveServiceNowOSFamily("Solaris"))
}

func TestClassifyServiceNowCI(t *testing.T) {
	assert.Equal(t, model.AssetTypeServer, classifyServiceNowCI("cmdb_ci_server"))
	assert.Equal(t, model.AssetTypeServer, classifyServiceNowCI("cmdb_ci_linux_server"))
	assert.Equal(t, model.AssetTypeWorkstation, classifyServiceNowCI("cmdb_ci_computer"))
	assert.Equal(t, model.AssetTypeNetworkDevice, classifyServiceNowCI("cmdb_ci_netgear"))
	assert.Equal(t, model.AssetTypeServer, classifyServiceNowCI("unknown_table"))
}
