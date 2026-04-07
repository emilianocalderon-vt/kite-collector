package dashboard

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
	"github.com/vulnertrack/kite-collector/internal/store/sqlite"
)

func testStore(t *testing.T) store.Store {
	t.Helper()
	st, err := sqlite.New(t.TempDir() + "/test.db")
	require.NoError(t, err)
	require.NoError(t, st.Migrate(context.Background()))
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func testContext() ReportContext {
	return ReportContext{
		AppName:    "kite-collector",
		AppVersion: "test",
	}
}

func TestRenderFindingsFragment_SeverityType(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Create a scan run first (findings reference it).
	runID := uuid.Must(uuid.NewV7())
	require.NoError(t, st.CreateScanRun(ctx, model.ScanRun{
		ID:        runID,
		StartedAt: time.Now().UTC(),
		Status:    model.ScanStatusRunning,
	}))

	// Create an asset (findings reference it).
	assetID := uuid.Must(uuid.NewV7())
	_, _, err := st.UpsertAssets(ctx, []model.Asset{{
		ID:              assetID,
		Hostname:        "test-host",
		AssetType:       model.AssetTypeServer,
		DiscoverySource: "test",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		FirstSeenAt:     time.Now().UTC(),
		LastSeenAt:      time.Now().UTC(),
	}})
	require.NoError(t, err)

	// Insert a finding with model.Severity (not plain string).
	findings := []model.ConfigFinding{{
		ID:          uuid.Must(uuid.NewV7()),
		AssetID:     assetID,
		ScanRunID:   runID,
		Auditor:     "ssh",
		CheckID:     "ssh-001",
		Title:       "Root login permitted",
		Severity:    model.SeverityHigh,
		CWEID:       "CWE-250",
		CWEName:     "Execution with Unnecessary Privileges",
		Evidence:    "PermitRootLogin yes",
		Remediation: "Set PermitRootLogin no",
		Timestamp:   time.Now().UTC(),
	}}
	require.NoError(t, st.InsertFindings(ctx, findings))

	// Render the findings fragment — this was crashing with
	// "wrong type for value; expected string; got model.Severity".
	var buf bytes.Buffer
	err = renderFindingsFragment(&buf, ctx, st, testContext())
	require.NoError(t, err, "renderFindingsFragment should not fail with model.Severity type")

	html := buf.String()
	assert.Contains(t, html, "ssh-001")
	assert.Contains(t, html, "Root login permitted")
	assert.Contains(t, html, "CWE-250")
	assert.Contains(t, html, "badge-orange") // high = orange
}

func TestRenderFindingsFragment_AllSeverities(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	runID := uuid.Must(uuid.NewV7())
	require.NoError(t, st.CreateScanRun(ctx, model.ScanRun{
		ID:        runID,
		StartedAt: time.Now().UTC(),
		Status:    model.ScanStatusRunning,
	}))

	assetID := uuid.Must(uuid.NewV7())
	_, _, err := st.UpsertAssets(ctx, []model.Asset{{
		ID:              assetID,
		Hostname:        "test-host",
		AssetType:       model.AssetTypeServer,
		DiscoverySource: "test",
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		FirstSeenAt:     time.Now().UTC(),
		LastSeenAt:      time.Now().UTC(),
	}})
	require.NoError(t, err)

	// Test all four severity levels render without error.
	for _, sev := range []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
	} {
		finding := model.ConfigFinding{
			ID:        uuid.Must(uuid.NewV7()),
			AssetID:   assetID,
			ScanRunID: runID,
			Auditor:   "test",
			CheckID:   "test-" + string(sev),
			Title:     "Test " + string(sev),
			Severity:  sev,
			CWEID:     "CWE-000",
			CWEName:   "Test",
			Evidence:  "test",
			Timestamp: time.Now().UTC(),
		}
		require.NoError(t, st.InsertFindings(ctx, []model.ConfigFinding{finding}))
	}

	var buf bytes.Buffer
	err = renderFindingsFragment(&buf, ctx, st, testContext())
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "badge-red")    // critical
	assert.Contains(t, html, "badge-orange") // high
	assert.Contains(t, html, "badge-yellow") // medium
	assert.Contains(t, html, "badge-blue")   // low
}

func TestFragmentEndpoints_NoSuperfluousWriteHeader(t *testing.T) {
	st := testStore(t)
	rc := testContext()
	srv := Serve(":0", st, rc, nil)

	// Test each fragment endpoint returns 200 with no errors.
	endpoints := []string{
		"/fragments/assets",
		"/fragments/software",
		"/fragments/findings",
		"/fragments/scans",
	}

	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, ep, nil)
			rec := httptest.NewRecorder()
			srv.Handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code,
				"endpoint %s should return 200", ep)
			assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
		})
	}
}
