package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// ---------------------------------------------------------------------------
// In-memory mock store
// ---------------------------------------------------------------------------

type mockStore struct {
	scanRun  *model.ScanRun
	software map[uuid.UUID][]model.InstalledSoftware
	assets   []model.Asset
	events   []model.AssetEvent
	mu       sync.Mutex
}

func newMockStore() *mockStore {
	return &mockStore{
		software: make(map[uuid.UUID][]model.InstalledSoftware),
	}
}

func (m *mockStore) UpsertAsset(_ context.Context, asset model.Asset) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.assets = append(m.assets, asset)
	return nil
}

func (m *mockStore) UpsertAssets(_ context.Context, assets []model.Asset) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.assets = append(m.assets, assets...)
	return len(assets), 0, nil
}

func (m *mockStore) GetAssetByNaturalKey(_ context.Context, _ string) (*model.Asset, error) {
	return nil, nil
}

func (m *mockStore) ListAssets(_ context.Context, _ store.AssetFilter) ([]model.Asset, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]model.Asset, len(m.assets))
	copy(cp, m.assets)
	return cp, nil
}

func (m *mockStore) GetStaleAssets(_ context.Context, _ time.Duration) ([]model.Asset, error) {
	return nil, nil
}

func (m *mockStore) InsertEvent(_ context.Context, event model.AssetEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *mockStore) InsertEvents(_ context.Context, events []model.AssetEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, events...)
	return nil
}

func (m *mockStore) ListEvents(_ context.Context, _ store.EventFilter) ([]model.AssetEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]model.AssetEvent, len(m.events))
	copy(cp, m.events)
	return cp, nil
}

func (m *mockStore) CreateScanRun(_ context.Context, run model.ScanRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanRun = &run
	return nil
}

func (m *mockStore) CompleteScanRun(_ context.Context, _ uuid.UUID, _ model.ScanResult) error {
	return nil
}

func (m *mockStore) GetLatestScanRun(_ context.Context) (*model.ScanRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.scanRun == nil {
		return nil, nil
	}
	cp := *m.scanRun
	return &cp, nil
}

func (m *mockStore) UpsertSoftware(_ context.Context, assetID uuid.UUID, sw []model.InstalledSoftware) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.software[assetID] = sw
	return nil
}

func (m *mockStore) ListSoftware(_ context.Context, assetID uuid.UUID) ([]model.InstalledSoftware, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.software[assetID], nil
}

func (m *mockStore) Migrate(_ context.Context) error { return nil }
func (m *mockStore) Close() error                    { return nil }

var _ store.Store = (*mockStore)(nil)

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestHealthEndpoint(t *testing.T) {
	ms := newMockStore()
	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "ok", body["status"])
}

func TestListAssets_EmptyStore(t *testing.T) {
	ms := newMockStore()
	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/assets", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Should return an empty JSON array, not null.
	var body []any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Len(t, body, 0)
}

func TestListAssets_ReturnsAssets(t *testing.T) {
	ms := newMockStore()
	now := time.Now().UTC().Truncate(time.Second)
	ms.assets = []model.Asset{
		{
			ID:              uuid.Must(uuid.NewV7()),
			Hostname:        "web-01",
			AssetType:       model.AssetTypeServer,
			IsAuthorized:    model.AuthorizationAuthorized,
			IsManaged:       model.ManagedManaged,
			DiscoverySource: "test",
			FirstSeenAt:     now,
			LastSeenAt:      now,
		},
		{
			ID:              uuid.Must(uuid.NewV7()),
			Hostname:        "db-01",
			AssetType:       model.AssetTypeServer,
			IsAuthorized:    model.AuthorizationUnknown,
			IsManaged:       model.ManagedUnknown,
			DiscoverySource: "test",
			FirstSeenAt:     now,
			LastSeenAt:      now,
		},
	}

	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/assets", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body []map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Len(t, body, 2)
}

func TestGetAssetByID_NotFound(t *testing.T) {
	ms := newMockStore()
	h := New(ms, nil)
	mux := h.Mux()

	unknownID := uuid.Must(uuid.NewV7())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/assets/"+unknownID.String(), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "asset not found", body["error"])
}

func TestGetAssetByID_Found(t *testing.T) {
	ms := newMockStore()
	assetID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Second)
	ms.assets = []model.Asset{
		{
			ID:              assetID,
			Hostname:        "found-host",
			AssetType:       model.AssetTypeServer,
			IsAuthorized:    model.AuthorizationAuthorized,
			IsManaged:       model.ManagedManaged,
			DiscoverySource: "test",
			FirstSeenAt:     now,
			LastSeenAt:      now,
		},
	}

	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/assets/"+assetID.String(), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "found-host", body["hostname"])
}

func TestGetAssetByID_InvalidUUID(t *testing.T) {
	ms := newMockStore()
	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/assets/not-a-uuid", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestListEvents_EmptyStore(t *testing.T) {
	ms := newMockStore()
	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/events", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body []any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Len(t, body, 0)
}

func TestLatestScan_NoScans(t *testing.T) {
	ms := newMockStore()
	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/scans/latest", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "no scan runs found", body["error"])
}

func TestLatestScan_ReturnsScan(t *testing.T) {
	ms := newMockStore()
	scanID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Second)
	ms.scanRun = &model.ScanRun{
		ID:        scanID,
		StartedAt: now,
		Status:    model.ScanStatusCompleted,
	}

	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/scans/latest", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, scanID.String(), body["id"])
	assert.Equal(t, string(model.ScanStatusCompleted), body["status"])
}

func TestListScans_Empty(t *testing.T) {
	ms := newMockStore()
	h := New(ms, nil)
	mux := h.Mux()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/scans", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body []any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Len(t, body, 0)
}
