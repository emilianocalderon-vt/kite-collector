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

// newMockIntuneAPI returns an httptest server that handles both the
// OAuth2 token endpoint and the Graph API managed devices endpoint.
func newMockIntuneAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// OAuth2 token endpoint.
	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.FormValue("client_secret") != "test-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-bearer-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	// Graph API managed devices — page 1.
	mux.HandleFunc("GET /v1.0/deviceManagement/managedDevices", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mock-bearer-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]string{
				{"deviceName": "LAPTOP-001", "operatingSystem": "Windows", "osVersion": "10.0.19044"},
				{"deviceName": "MAC-002", "operatingSystem": "macOS", "osVersion": "13.4"},
			},
			// No @odata.nextLink — single page.
		})
	})

	return httptest.NewServer(mux)
}

// newMockIntunePaginatedAPI returns a server with two pages of results.
func newMockIntunePaginatedAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-bearer-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	var srv *httptest.Server
	callCount := 0
	mux.HandleFunc("GET /v1.0/deviceManagement/managedDevices", func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]string{
					{"deviceName": "DEV-A", "operatingSystem": "Windows", "osVersion": "11.0"},
				},
				"@odata.nextLink": srv.URL + "/v1.0/deviceManagement/managedDevices?page=2",
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]string{
					{"deviceName": "DEV-B", "operatingSystem": "Linux", "osVersion": "22.04"},
				},
			})
		}
	})

	srv = httptest.NewServer(mux)
	return srv
}

func TestIntune_Name(t *testing.T) {
	assert.Equal(t, "intune", NewIntune().Name())
}

func TestIntune_Discover_Success(t *testing.T) {
	srv := newMockIntuneAPI(t)
	defer srv.Close()

	i := NewIntune()
	i.tokenBaseURL = srv.URL
	i.graphBaseURL = srv.URL

	cfg := map[string]any{
		"tenant_id":     "test-tenant",
		"client_id":     "test-client",
		"client_secret": "test-secret",
	}

	assets, err := i.Discover(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, assets, 2)

	// Windows device.
	laptop := findAsset(assets, "LAPTOP-001")
	require.NotNil(t, laptop)
	assert.Equal(t, model.AssetTypeWorkstation, laptop.AssetType)
	assert.Equal(t, "windows", laptop.OSFamily)
	assert.Equal(t, "10.0.19044", laptop.OSVersion)
	assert.Equal(t, "intune", laptop.DiscoverySource)
	assert.Equal(t, model.AuthorizationUnknown, laptop.IsAuthorized)
	assert.Equal(t, model.ManagedManaged, laptop.IsManaged)
	assert.NotEmpty(t, laptop.NaturalKey)

	// macOS device.
	mac := findAsset(assets, "MAC-002")
	require.NotNil(t, mac)
	assert.Equal(t, "darwin", mac.OSFamily)
}

func TestIntune_Discover_MissingCredentials(t *testing.T) {
	i := NewIntune()

	assets, err := i.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestIntune_Discover_TokenFailure(t *testing.T) {
	srv := newMockIntuneAPI(t)
	defer srv.Close()

	i := NewIntune()
	i.tokenBaseURL = srv.URL
	i.graphBaseURL = srv.URL

	cfg := map[string]any{
		"tenant_id":     "test-tenant",
		"client_id":     "test-client",
		"client_secret": "wrong-secret",
	}

	// Token failure → graceful degradation (nil, nil).
	assets, err := i.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestIntune_Discover_Pagination(t *testing.T) {
	srv := newMockIntunePaginatedAPI(t)
	defer srv.Close()

	i := NewIntune()
	i.tokenBaseURL = srv.URL
	i.graphBaseURL = srv.URL

	cfg := map[string]any{
		"tenant_id":     "test-tenant",
		"client_id":     "test-client",
		"client_secret": "test-secret",
	}

	assets, err := i.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Len(t, assets, 2)
	assert.NotNil(t, findAsset(assets, "DEV-A"))
	assert.NotNil(t, findAsset(assets, "DEV-B"))
}

func TestIntune_Discover_MalformedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[{"bad": true}]}`))
	}))
	defer srv.Close()

	i := NewIntune()
	i.tokenBaseURL = srv.URL
	i.graphBaseURL = srv.URL

	cfg := map[string]any{
		"tenant_id":     "t",
		"client_id":     "c",
		"client_secret": "s",
	}

	// Malformed entries are skipped, not errors.
	assets, err := i.Discover(context.Background(), cfg)
	require.NoError(t, err)
	// The device has no deviceName but still parses — just empty hostname.
	assert.Len(t, assets, 1)
}

func TestDeriveIntuneOSFamily(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Windows", "windows"},
		{"macOS", "darwin"},
		{"iOS", "darwin"},
		{"iPadOS", "darwin"},
		{"Android", "linux"},
		{"Linux", "linux"},
		{"ChromeOS", "chromeos"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, deriveIntuneOSFamily(tt.input))
		})
	}
}

func TestClassifyIntuneDevice(t *testing.T) {
	assert.Equal(t, model.AssetTypeWorkstation, classifyIntuneDevice("Windows"))
	assert.Equal(t, model.AssetTypeWorkstation, classifyIntuneDevice("macOS"))
	assert.Equal(t, model.AssetTypeWorkstation, classifyIntuneDevice("Android"))
}

// findAsset returns the first asset matching hostname, or nil.
func findAsset(assets []model.Asset, hostname string) *model.Asset {
	for i := range assets {
		if assets[i].Hostname == hostname {
			return &assets[i]
		}
	}
	return nil
}
