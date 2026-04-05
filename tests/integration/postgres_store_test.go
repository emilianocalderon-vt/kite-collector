//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
	"github.com/vulnertrack/kite-collector/internal/store/postgres"
)

// newTestStore creates a PostgresStore from the KITE_TEST_POSTGRES_DSN env var,
// runs migrations, and registers a cleanup that closes the store.
func newTestStore(t *testing.T) *postgres.PostgresStore {
	t.Helper()

	dsn := os.Getenv("KITE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KITE_TEST_POSTGRES_DSN not set; skipping postgres integration test")
	}

	st, err := postgres.New(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	ctx := context.Background()
	require.NoError(t, st.Migrate(ctx))

	return st
}

// makeAsset builds a minimal Asset with a computed natural key.
func makeAsset(hostname string, assetType model.AssetType) model.Asset {
	now := time.Now().UTC().Truncate(time.Millisecond)
	a := model.Asset{
		ID:              uuid.New(),
		Hostname:        hostname,
		AssetType:       assetType,
		FirstSeenAt:     now,
		LastSeenAt:      now,
		OSFamily:        "linux",
		OSVersion:       "6.1",
		Environment:     "production",
		Owner:           "secops",
		Criticality:     "high",
		DiscoverySource: "nmap",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            "[]",
	}
	a.ComputeNaturalKey()
	return a
}

// ---------------------------------------------------------------------------
// UpsertAssets / ListAssets
// ---------------------------------------------------------------------------

func TestUpsertAssets_InsertAndUpdate(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	a1 := makeAsset("pg-test-host-01", model.AssetTypeServer)
	a2 := makeAsset("pg-test-host-02", model.AssetTypeWorkstation)

	inserted, updated, err := st.UpsertAssets(ctx, []model.Asset{a1, a2})
	require.NoError(t, err)
	assert.Equal(t, 2, inserted)
	assert.Equal(t, 0, updated)

	// Upsert the same assets again -- should count as updates.
	a1.OSVersion = "6.2"
	a1.LastSeenAt = time.Now().UTC().Truncate(time.Millisecond)
	inserted, updated, err = st.UpsertAssets(ctx, []model.Asset{a1, a2})
	require.NoError(t, err)
	assert.Equal(t, 0, inserted)
	assert.Equal(t, 2, updated)
}

func TestListAssets_FilterByHostname(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	a := makeAsset("pg-list-filter-host", model.AssetTypeServer)
	_, _, err := st.UpsertAssets(ctx, []model.Asset{a})
	require.NoError(t, err)

	results, err := st.ListAssets(ctx, store.AssetFilter{
		Hostname: "pg-list-filter-host",
		Limit:    10,
	})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "pg-list-filter-host", results[0].Hostname)
}

func TestListAssets_FilterByAssetType(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	a := makeAsset("pg-type-filter-host", model.AssetTypeContainer)
	_, _, err := st.UpsertAssets(ctx, []model.Asset{a})
	require.NoError(t, err)

	results, err := st.ListAssets(ctx, store.AssetFilter{
		AssetType: string(model.AssetTypeContainer),
		Limit:     10,
	})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	for _, r := range results {
		assert.Equal(t, model.AssetTypeContainer, r.AssetType)
	}
}

// ---------------------------------------------------------------------------
// GetStaleAssets
// ---------------------------------------------------------------------------

func TestGetStaleAssets(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	staleAsset := makeAsset("pg-stale-host", model.AssetTypeServer)
	staleAsset.LastSeenAt = time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Millisecond)

	freshAsset := makeAsset("pg-fresh-host", model.AssetTypeServer)
	freshAsset.LastSeenAt = time.Now().UTC().Truncate(time.Millisecond)

	_, _, err := st.UpsertAssets(ctx, []model.Asset{staleAsset, freshAsset})
	require.NoError(t, err)

	stale, err := st.GetStaleAssets(ctx, 24*time.Hour)
	require.NoError(t, err)

	staleHostnames := make(map[string]bool)
	for _, a := range stale {
		staleHostnames[a.Hostname] = true
	}
	assert.True(t, staleHostnames["pg-stale-host"], "stale asset should appear in results")
	assert.False(t, staleHostnames["pg-fresh-host"], "fresh asset should not appear in stale results")
}

// ---------------------------------------------------------------------------
// InsertEvents / ListEvents
// ---------------------------------------------------------------------------

func TestInsertEvents_AndListByAssetID(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	asset := makeAsset("pg-event-host", model.AssetTypeServer)
	_, _, err := st.UpsertAssets(ctx, []model.Asset{asset})
	require.NoError(t, err)

	scanRunID := uuid.New()
	events := []model.AssetEvent{
		{
			ID:        uuid.New(),
			AssetID:   asset.ID,
			ScanRunID: scanRunID,
			EventType: model.EventAssetDiscovered,
			Severity:  model.SeverityLow,
			Timestamp: time.Now().UTC().Truncate(time.Millisecond),
			Details:   `{"source":"nmap"}`,
		},
		{
			ID:        uuid.New(),
			AssetID:   asset.ID,
			ScanRunID: scanRunID,
			EventType: model.EventAssetUpdated,
			Severity:  model.SeverityLow,
			Timestamp: time.Now().UTC().Truncate(time.Millisecond),
			Details:   `{"field":"os_version"}`,
		},
	}

	err = st.InsertEvents(ctx, events)
	require.NoError(t, err)

	listed, err := st.ListEvents(ctx, store.EventFilter{
		AssetID: &asset.ID,
		Limit:   10,
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(listed), 2)
}

func TestListEvents_FilterByScanRunID(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	asset := makeAsset("pg-event-scan-host", model.AssetTypeServer)
	_, _, err := st.UpsertAssets(ctx, []model.Asset{asset})
	require.NoError(t, err)

	scanRunID := uuid.New()
	otherScanRunID := uuid.New()

	events := []model.AssetEvent{
		{
			ID:        uuid.New(),
			AssetID:   asset.ID,
			ScanRunID: scanRunID,
			EventType: model.EventAssetDiscovered,
			Severity:  model.SeverityLow,
			Timestamp: time.Now().UTC().Truncate(time.Millisecond),
			Details:   "{}",
		},
		{
			ID:        uuid.New(),
			AssetID:   asset.ID,
			ScanRunID: otherScanRunID,
			EventType: model.EventAssetUpdated,
			Severity:  model.SeverityLow,
			Timestamp: time.Now().UTC().Truncate(time.Millisecond),
			Details:   "{}",
		},
	}
	require.NoError(t, st.InsertEvents(ctx, events))

	listed, err := st.ListEvents(ctx, store.EventFilter{
		ScanRunID: &scanRunID,
		Limit:     10,
	})
	require.NoError(t, err)
	for _, ev := range listed {
		assert.Equal(t, scanRunID, ev.ScanRunID)
	}
}

// ---------------------------------------------------------------------------
// CreateScanRun / CompleteScanRun / GetLatestScanRun
// ---------------------------------------------------------------------------

func TestScanRun_CreateCompleteAndGetLatest(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	run := model.ScanRun{
		ID:               uuid.New(),
		StartedAt:        time.Now().UTC().Truncate(time.Millisecond),
		Status:           model.ScanStatusRunning,
		DiscoverySources: mustJSON([]string{"nmap", "cloud-api"}),
		ScopeConfig:      `{"subnets":["10.0.0.0/24"]}`,
	}
	require.NoError(t, st.CreateScanRun(ctx, run))

	// Complete the scan run.
	result := model.ScanResult{
		TotalAssets:     42,
		NewAssets:       10,
		UpdatedAssets:   30,
		StaleAssets:     2,
		EventsEmitted:   52,
		CoveragePercent: 95.5,
	}
	require.NoError(t, st.CompleteScanRun(ctx, run.ID, result))

	// Retrieve latest and verify fields.
	latest, err := st.GetLatestScanRun(ctx)
	require.NoError(t, err)
	require.NotNil(t, latest)
	assert.Equal(t, run.ID, latest.ID)
	assert.Equal(t, model.ScanStatusCompleted, latest.Status)
	assert.Equal(t, 42, latest.TotalAssets)
	assert.Equal(t, 10, latest.NewAssets)
	assert.NotNil(t, latest.CompletedAt)
}

// ---------------------------------------------------------------------------
// UpsertSoftware / ListSoftware
// ---------------------------------------------------------------------------

func TestUpsertSoftware_AndList(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	asset := makeAsset("pg-software-host", model.AssetTypeServer)
	_, _, err := st.UpsertAssets(ctx, []model.Asset{asset})
	require.NoError(t, err)

	software := []model.InstalledSoftware{
		{
			ID:             uuid.New(),
			AssetID:        asset.ID,
			SoftwareName:   "CrowdStrike Falcon",
			Vendor:         "CrowdStrike",
			Version:        "7.0.1",
			CPE23:          "cpe:2.3:a:crowdstrike:falcon:7.0.1:*:*:*:*:*:*:*",
			PackageManager: "msi",
		},
		{
			ID:             uuid.New(),
			AssetID:        asset.ID,
			SoftwareName:   "osquery",
			Vendor:         "Meta",
			Version:        "5.11.0",
			CPE23:          "",
			PackageManager: "deb",
		},
	}
	require.NoError(t, st.UpsertSoftware(ctx, asset.ID, software))

	listed, err := st.ListSoftware(ctx, asset.ID)
	require.NoError(t, err)
	assert.Len(t, listed, 2)

	names := make(map[string]bool)
	for _, sw := range listed {
		names[sw.SoftwareName] = true
	}
	assert.True(t, names["CrowdStrike Falcon"])
	assert.True(t, names["osquery"])
}

func TestUpsertSoftware_ReplacesExisting(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	asset := makeAsset("pg-software-replace-host", model.AssetTypeServer)
	_, _, err := st.UpsertAssets(ctx, []model.Asset{asset})
	require.NoError(t, err)

	// Initial software set.
	initial := []model.InstalledSoftware{
		{
			ID:           uuid.New(),
			AssetID:      asset.ID,
			SoftwareName: "old-agent",
			Vendor:       "OldCorp",
			Version:      "1.0.0",
		},
	}
	require.NoError(t, st.UpsertSoftware(ctx, asset.ID, initial))

	listed, err := st.ListSoftware(ctx, asset.ID)
	require.NoError(t, err)
	assert.Len(t, listed, 1)
	assert.Equal(t, "old-agent", listed[0].SoftwareName)

	// Replace with a completely new set.
	replacement := []model.InstalledSoftware{
		{
			ID:           uuid.New(),
			AssetID:      asset.ID,
			SoftwareName: "new-edr",
			Vendor:       "NewCorp",
			Version:      "2.0.0",
		},
		{
			ID:           uuid.New(),
			AssetID:      asset.ID,
			SoftwareName: "config-mgmt",
			Vendor:       "NewCorp",
			Version:      "3.0.0",
		},
	}
	require.NoError(t, st.UpsertSoftware(ctx, asset.ID, replacement))

	listed, err = st.ListSoftware(ctx, asset.ID)
	require.NoError(t, err)
	assert.Len(t, listed, 2)

	names := make(map[string]bool)
	for _, sw := range listed {
		names[sw.SoftwareName] = true
	}
	assert.False(t, names["old-agent"], "old software should have been replaced")
	assert.True(t, names["new-edr"])
	assert.True(t, names["config-mgmt"])
}

// mustJSON marshals v to a JSON string, panicking on error.
func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
