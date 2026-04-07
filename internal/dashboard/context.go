// Package dashboard provides an embedded browser-based UI for viewing
// kite-collector scan results. It serves a single-page HTMX application
// with HTML fragment endpoints and CSV export capabilities.
//
// All static assets are compiled into the binary via go:embed — the
// dashboard works fully offline with zero external dependencies.
package dashboard

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/store"
)

// ReportContext holds all metadata rendered in the dashboard header, footer,
// and CSV export headers. A new ReportID is generated per dashboard session.
type ReportContext struct {
	// Application
	AppName    string
	AppVersion string
	Commit     string

	// Host
	Hostname string
	OS       string
	Arch     string

	// Database
	DBPath string
	DBSize string

	// Report
	ReportID       string
	GeneratedAtUTC string
	GeneratedAtLocal string

	// Latest scan
	ScanRunID     string
	ScanStartedAt string
	ScanStatus    string
	TotalAssets   int
	TotalSoftware int
	TotalFindings int
	StaleAssets   int
}

// NewReportContext builds a ReportContext from the current environment and
// store state. The ReportID is a fresh UUID v7.
func NewReportContext(ctx context.Context, st store.Store, dbPath, version, commit string) ReportContext {
	hostname, _ := os.Hostname()

	rc := ReportContext{
		AppName:     "kite-collector",
		AppVersion:  version,
		Commit:      commit,
		Hostname:    hostname,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		DBPath:      dbPath,
		ReportID:         uuid.Must(uuid.NewV7()).String(),
		GeneratedAtUTC:   time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		GeneratedAtLocal: time.Now().Local().Format("2006-01-02 15:04:05 MST"),
	}

	// Database file size.
	if info, err := os.Stat(dbPath); err == nil {
		rc.DBSize = humanSize(info.Size())
	}

	// Latest scan run.
	if run, err := st.GetLatestScanRun(ctx); err == nil && run != nil {
		rc.ScanRunID = run.ID.String()
		rc.ScanStartedAt = run.StartedAt.Format(time.RFC3339)
		rc.ScanStatus = string(run.Status)
		rc.TotalAssets = run.TotalAssets
		rc.StaleAssets = run.StaleAssets
	}

	// Counts.
	if assets, err := st.ListAssets(ctx, store.AssetFilter{}); err == nil {
		rc.TotalAssets = len(assets)
	}
	if findings, err := st.ListFindings(ctx, store.FindingFilter{}); err == nil {
		rc.TotalFindings = len(findings)
	}

	return rc
}

// humanSize formats a byte count as a human-readable string.
func humanSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
