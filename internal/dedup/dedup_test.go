package dedup

import (
	"context"
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
	assets map[string]model.Asset // keyed by natural_key
	mu     sync.Mutex
}

func newMockStore() *mockStore {
	return &mockStore{assets: make(map[string]model.Asset)}
}

func (m *mockStore) UpsertAsset(_ context.Context, asset model.Asset) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	asset.ComputeNaturalKey()
	m.assets[asset.NaturalKey] = asset
	return nil
}

func (m *mockStore) UpsertAssets(_ context.Context, assets []model.Asset) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var inserted, updated int
	for i := range assets {
		assets[i].ComputeNaturalKey()
		if _, exists := m.assets[assets[i].NaturalKey]; exists {
			updated++
		} else {
			inserted++
		}
		m.assets[assets[i].NaturalKey] = assets[i]
	}
	return inserted, updated, nil
}

func (m *mockStore) GetAssetByNaturalKey(_ context.Context, key string) (*model.Asset, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.assets[key]
	if !ok {
		return nil, nil
	}
	cp := a
	return &cp, nil
}

func (m *mockStore) GetAssetByID(_ context.Context, id uuid.UUID) (*model.Asset, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.assets {
		if a.ID == id {
			cp := a
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (m *mockStore) ListAssets(_ context.Context, _ store.AssetFilter) ([]model.Asset, error) {
	return nil, nil
}

func (m *mockStore) GetStaleAssets(_ context.Context, _ time.Duration) ([]model.Asset, error) {
	return nil, nil
}

func (m *mockStore) InsertEvent(_ context.Context, _ model.AssetEvent) error { return nil }

func (m *mockStore) InsertEvents(_ context.Context, _ []model.AssetEvent) error { return nil }

func (m *mockStore) ListEvents(_ context.Context, _ store.EventFilter) ([]model.AssetEvent, error) {
	return nil, nil
}

func (m *mockStore) CreateScanRun(_ context.Context, _ model.ScanRun) error { return nil }

func (m *mockStore) CompleteScanRun(_ context.Context, _ uuid.UUID, _ model.ScanResult) error {
	return nil
}

func (m *mockStore) GetLatestScanRun(_ context.Context) (*model.ScanRun, error) { return nil, nil }

func (m *mockStore) UpsertSoftware(_ context.Context, _ uuid.UUID, _ []model.InstalledSoftware) error {
	return nil
}

func (m *mockStore) ListSoftware(_ context.Context, _ uuid.UUID) ([]model.InstalledSoftware, error) {
	return nil, nil
}

func (m *mockStore) InsertFindings(_ context.Context, _ []model.ConfigFinding) error { return nil }

func (m *mockStore) ListFindings(_ context.Context, _ store.FindingFilter) ([]model.ConfigFinding, error) {
	return nil, nil
}

func (m *mockStore) InsertPostureAssessments(_ context.Context, _ []model.PostureAssessment) error {
	return nil
}

func (m *mockStore) ListPostureAssessments(_ context.Context, _ store.PostureFilter) ([]model.PostureAssessment, error) {
	return nil, nil
}

func (m *mockStore) InsertRuntimeIncident(_ context.Context, _ model.RuntimeIncident) error {
	return nil
}

func (m *mockStore) ListRuntimeIncidents(_ context.Context, _ store.IncidentFilter) ([]model.RuntimeIncident, error) {
	return nil, nil
}

func (m *mockStore) Migrate(_ context.Context) error { return nil }

func (m *mockStore) Close() error { return nil }

// compile-time check
var _ store.Store = (*mockStore)(nil)

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestDedup_NewAssetGetsUUIDv7(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	assets := []model.Asset{
		{Hostname: "new-host", AssetType: model.AssetTypeServer, DiscoverySource: "test"},
	}

	res, err := dd.Deduplicate(ctx, assets)
	require.NoError(t, err)
	require.Len(t, res.Assets, 1)

	assert.NotEqual(t, uuid.Nil, res.Assets[0].ID, "new asset must get a UUID assigned")
	assert.Equal(t, 1, res.NewCount)
	assert.Equal(t, 0, res.UpdatedCount)
}

func TestDedup_ExistingAssetPreservesID(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	// Pre-populate the store with an existing asset.
	existingID := uuid.Must(uuid.NewV7())
	firstSeen := time.Now().UTC().Add(-24 * time.Hour)
	existing := model.Asset{
		ID:              existingID,
		Hostname:        "db-01",
		AssetType:       model.AssetTypeServer,
		DiscoverySource: "network",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      firstSeen,
	}
	existing.ComputeNaturalKey()
	ms.assets[existing.NaturalKey] = existing

	// Re-discover the same asset.
	incoming := []model.Asset{
		{Hostname: "db-01", AssetType: model.AssetTypeServer, DiscoverySource: "network"},
	}

	res, err := dd.Deduplicate(ctx, incoming)
	require.NoError(t, err)
	require.Len(t, res.Assets, 1)

	assert.Equal(t, existingID, res.Assets[0].ID, "existing ID must be preserved")
	assert.Equal(t, 0, res.NewCount)
	assert.Equal(t, 1, res.UpdatedCount)
}

func TestDedup_FirstSeenAtPreservedOnUpdate(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	firstSeen := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	existing := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "app-01",
		AssetType:       model.AssetTypeContainer,
		DiscoverySource: "agent",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      firstSeen,
	}
	existing.ComputeNaturalKey()
	ms.assets[existing.NaturalKey] = existing

	incoming := []model.Asset{
		{Hostname: "app-01", AssetType: model.AssetTypeContainer, DiscoverySource: "agent"},
	}

	res, err := dd.Deduplicate(ctx, incoming)
	require.NoError(t, err)
	require.Len(t, res.Assets, 1)

	assert.Equal(t, firstSeen, res.Assets[0].FirstSeenAt,
		"FirstSeenAt must be preserved from the existing record")
}

func TestDedup_LastSeenAtUpdatedOnRediscovery(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	oldTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	existing := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "app-02",
		AssetType:       model.AssetTypeServer,
		DiscoverySource: "network",
		FirstSeenAt:     oldTime,
		LastSeenAt:      oldTime,
	}
	existing.ComputeNaturalKey()
	ms.assets[existing.NaturalKey] = existing

	beforeDedup := time.Now().UTC()
	incoming := []model.Asset{
		{Hostname: "app-02", AssetType: model.AssetTypeServer, DiscoverySource: "network"},
	}

	res, err := dd.Deduplicate(ctx, incoming)
	require.NoError(t, err)
	require.Len(t, res.Assets, 1)

	assert.True(t, res.Assets[0].LastSeenAt.After(oldTime) || res.Assets[0].LastSeenAt.Equal(beforeDedup),
		"LastSeenAt must be updated to approximately now")
}

func TestDedup_IntraBatchDedup(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	// Two assets with the same hostname+type in one batch
	assets := []model.Asset{
		{Hostname: "dup-host", AssetType: model.AssetTypeWorkstation, DiscoverySource: "src1"},
		{Hostname: "dup-host", AssetType: model.AssetTypeWorkstation, DiscoverySource: "src2"},
	}

	res, err := dd.Deduplicate(ctx, assets)
	require.NoError(t, err)

	assert.Len(t, res.Assets, 1, "duplicate within a batch must be collapsed to one")
	assert.Equal(t, 1, res.NewCount)
	assert.Equal(t, 0, res.UpdatedCount)
}

func TestDedup_IntraBatchDedup_DifferentTypes(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	// Same hostname but different types are distinct assets
	assets := []model.Asset{
		{Hostname: "host-01", AssetType: model.AssetTypeServer, DiscoverySource: "net"},
		{Hostname: "host-01", AssetType: model.AssetTypeContainer, DiscoverySource: "net"},
	}

	res, err := dd.Deduplicate(ctx, assets)
	require.NoError(t, err)

	assert.Len(t, res.Assets, 2, "same hostname with different types are distinct")
	assert.Equal(t, 2, res.NewCount)
}

func TestDedup_EmptyInput(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	res, err := dd.Deduplicate(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, res.Assets)
	assert.Equal(t, 0, res.NewCount)
	assert.Equal(t, 0, res.UpdatedCount)

	res2, err := dd.Deduplicate(ctx, []model.Asset{})
	require.NoError(t, err)
	assert.Empty(t, res2.Assets)
	assert.Equal(t, 0, res2.NewCount)
	assert.Equal(t, 0, res2.UpdatedCount)
}

func TestDedup_NewAssetFirstSeenEqualsLastSeen(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	assets := []model.Asset{
		{Hostname: "fresh-host", AssetType: model.AssetTypeWorkstation, DiscoverySource: "test"},
	}

	res, err := dd.Deduplicate(ctx, assets)
	require.NoError(t, err)
	require.Len(t, res.Assets, 1)

	assert.Equal(t, res.Assets[0].FirstSeenAt, res.Assets[0].LastSeenAt,
		"for a new asset, FirstSeenAt must equal LastSeenAt")
	assert.False(t, res.Assets[0].FirstSeenAt.IsZero(), "timestamps must not be zero")
}

func TestDedup_MergesOSInfo(t *testing.T) {
	ms := newMockStore()
	dd := New(ms, nil)
	ctx := context.Background()

	existing := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        "merge-host",
		AssetType:       model.AssetTypeServer,
		DiscoverySource: "network",
		OSFamily:        "",
		FirstSeenAt:     time.Now().UTC().Add(-time.Hour),
		LastSeenAt:      time.Now().UTC().Add(-time.Hour),
	}
	existing.ComputeNaturalKey()
	ms.assets[existing.NaturalKey] = existing

	incoming := []model.Asset{
		{
			Hostname:        "merge-host",
			AssetType:       model.AssetTypeServer,
			DiscoverySource: "agent",
			OSFamily:        "linux",
			OSVersion:       "6.1",
		},
	}

	res, err := dd.Deduplicate(ctx, incoming)
	require.NoError(t, err)
	require.Len(t, res.Assets, 1)

	assert.Equal(t, "linux", res.Assets[0].OSFamily, "OS family must be merged from incoming")
	assert.Equal(t, "6.1", res.Assets[0].OSVersion, "OS version must be merged from incoming")
}
