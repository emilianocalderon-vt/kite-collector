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

func newMockSCCMAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /AdminService/v1.0/Device", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "sccm-user" || pass != "sccm-pass" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"Name":                          "WIN-SRV-01",
					"OperatingSystemNameandVersion": "Microsoft Windows Server 2022",
					"LastActiveTime":                "2026-04-01T10:00:00Z",
					"IsClient":                      true,
				},
				{
					"Name":                          "WIN-WS-01",
					"OperatingSystemNameandVersion": "Microsoft Windows 11 Enterprise",
					"LastActiveTime":                "2026-04-02T12:00:00Z",
					"IsClient":                      true,
				},
				{
					"Name":                          "UNMANAGED-01",
					"OperatingSystemNameandVersion": "Microsoft Windows 10",
					"LastActiveTime":                "2026-03-15T08:00:00Z",
					"IsClient":                      false,
				},
			},
		})
	})

	return httptest.NewServer(mux)
}

func TestSCCM_Name(t *testing.T) {
	assert.Equal(t, "sccm", NewSCCM().Name())
}

func TestSCCM_Discover_Success(t *testing.T) {
	srv := newMockSCCMAPI(t)
	defer srv.Close()

	s := NewSCCM()
	cfg := map[string]any{
		"api_url":  srv.URL,
		"username": "sccm-user",
		"password": "sccm-pass",
	}

	assets, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	require.Len(t, assets, 3)

	// Server with IsClient=true → managed.
	winSrv := findAsset(assets, "WIN-SRV-01")
	require.NotNil(t, winSrv)
	assert.Equal(t, model.AssetTypeServer, winSrv.AssetType)
	assert.Equal(t, "windows", winSrv.OSFamily)
	assert.Equal(t, model.ManagedManaged, winSrv.IsManaged)
	assert.Equal(t, "sccm", winSrv.DiscoverySource)
	assert.NotEmpty(t, winSrv.NaturalKey)

	// Workstation with IsClient=true → managed.
	winWS := findAsset(assets, "WIN-WS-01")
	require.NotNil(t, winWS)
	assert.Equal(t, model.AssetTypeWorkstation, winWS.AssetType)
	assert.Equal(t, model.ManagedManaged, winWS.IsManaged)

	// IsClient=false → unknown management.
	unmanaged := findAsset(assets, "UNMANAGED-01")
	require.NotNil(t, unmanaged)
	assert.Equal(t, model.ManagedUnknown, unmanaged.IsManaged)
}

func TestSCCM_Discover_MissingCredentials(t *testing.T) {
	s := NewSCCM()

	assets, err := s.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestSCCM_Discover_AuthFailure(t *testing.T) {
	srv := newMockSCCMAPI(t)
	defer srv.Close()

	s := NewSCCM()
	cfg := map[string]any{
		"api_url":  srv.URL,
		"username": "sccm-user",
		"password": "wrong",
	}

	// Auth failure → nil (graceful).
	assets, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Nil(t, assets)
}

func TestSCCM_Discover_MalformedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[{"invalid": true}]}`))
	}))
	defer srv.Close()

	s := NewSCCM()
	cfg := map[string]any{
		"api_url":  srv.URL,
		"username": "u",
		"password": "p",
	}

	// Malformed entries are skipped.
	assets, err := s.Discover(context.Background(), cfg)
	require.NoError(t, err)
	assert.Len(t, assets, 1) // entry parses but with empty Name
}

func TestDeriveSCCMOSFamily(t *testing.T) {
	assert.Equal(t, "windows", deriveSCCMOSFamily("Microsoft Windows Server 2022"))
	assert.Equal(t, "linux", deriveSCCMOSFamily("Ubuntu Linux 22.04"))
	assert.Equal(t, "linux", deriveSCCMOSFamily("Red Hat Enterprise Linux"))
	assert.Equal(t, "darwin", deriveSCCMOSFamily("macOS 14"))
	assert.Equal(t, "windows", deriveSCCMOSFamily("Unknown OS")) // default
}

func TestClassifySCCMDevice(t *testing.T) {
	assert.Equal(t, model.AssetTypeServer, classifySCCMDevice("Microsoft Windows Server 2022"))
	assert.Equal(t, model.AssetTypeWorkstation, classifySCCMDevice("Microsoft Windows 11"))
}
