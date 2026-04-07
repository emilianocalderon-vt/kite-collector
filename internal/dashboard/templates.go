package dashboard

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/store"
)

// templateFuncs provides helper functions for HTML templates.
var templateFuncs = template.FuncMap{
	"upper": strings.ToUpper,
	"formatTime": func(t time.Time) string {
		return t.Format("2006-01-02 15:04:05")
	},
	"severityClass": func(s model.Severity) string {
		switch s {
		case model.SeverityCritical:
			return "badge-red"
		case model.SeverityHigh:
			return "badge-orange"
		case model.SeverityMedium:
			return "badge-yellow"
		case model.SeverityLow:
			return "badge-blue"
		default:
			return "badge-gray"
		}
	},
	"authClass": func(a model.AuthorizationState) string {
		switch a {
		case model.AuthorizationAuthorized:
			return "badge-green"
		case model.AuthorizationUnauthorized:
			return "badge-red"
		case model.AuthorizationUnknown:
			return "badge-yellow"
		}
		return "badge-yellow"
	},
}

// renderAssetsFragment renders the assets table as an HTML fragment.
func renderAssetsFragment(w io.Writer, ctx context.Context, st store.Store, rc ReportContext) error {
	assets, err := st.ListAssets(ctx, store.AssetFilter{Limit: 500})
	if err != nil {
		return fmt.Errorf("list assets: %w", err)
	}

	tmpl := template.Must(template.New("assets").Funcs(templateFuncs).Parse(assetsTemplate))
	return tmpl.Execute(w, map[string]any{
		"Assets":  assets,
		"Context": rc,
	})
}

// renderSoftwareFragment renders the software table as an HTML fragment.
func renderSoftwareFragment(w io.Writer, ctx context.Context, st store.Store, rc ReportContext) error {
	// Collect software across all assets.
	assets, err := st.ListAssets(ctx, store.AssetFilter{Limit: 100})
	if err != nil {
		return fmt.Errorf("list assets: %w", err)
	}

	type softwareRow struct {
		Hostname       string
		SoftwareName   string
		Version        string
		PackageManager string
		CPE23          string
	}

	var rows []softwareRow
	for _, a := range assets {
		sw, swErr := st.ListSoftware(ctx, a.ID)
		if swErr != nil {
			continue
		}
		for _, s := range sw {
			rows = append(rows, softwareRow{
				Hostname:       a.Hostname,
				SoftwareName:   s.SoftwareName,
				Version:        s.Version,
				PackageManager: s.PackageManager,
				CPE23:          s.CPE23,
			})
			if len(rows) >= 500 {
				break
			}
		}
		if len(rows) >= 500 {
			break
		}
	}

	tmpl := template.Must(template.New("software").Funcs(templateFuncs).Parse(softwareTemplate))
	return tmpl.Execute(w, map[string]any{
		"Software": rows,
		"Context":  rc,
	})
}

// renderFindingsFragment renders the findings table as an HTML fragment.
func renderFindingsFragment(w io.Writer, ctx context.Context, st store.Store, rc ReportContext) error {
	findings, err := st.ListFindings(ctx, store.FindingFilter{Limit: 500})
	if err != nil {
		return fmt.Errorf("list findings: %w", err)
	}

	tmpl := template.Must(template.New("findings").Funcs(templateFuncs).Parse(findingsTemplate))
	return tmpl.Execute(w, map[string]any{
		"Findings": findings,
		"Context":  rc,
	})
}

// renderScansFragment renders the scan history table as an HTML fragment.
func renderScansFragment(w io.Writer, ctx context.Context, st store.Store, rc ReportContext) error {
	// Get latest scan for now — in a full implementation this would list all.
	run, err := st.GetLatestScanRun(ctx)
	if err != nil {
		return fmt.Errorf("get latest scan: %w", err)
	}

	var runs []model.ScanRun
	if run != nil {
		runs = append(runs, *run)
	}

	tmpl := template.Must(template.New("scans").Funcs(templateFuncs).Parse(scansTemplate))
	return tmpl.Execute(w, map[string]any{
		"Scans":   runs,
		"Context": rc,
	})
}

// HTML fragment templates — returned by HTMX endpoints.

const assetsTemplate = `<h2>Assets ({{len .Assets}})</h2>
<div class="table-actions">
  <a href="/api/v1/assets/export.csv" class="btn">Export CSV</a>
</div>
<table>
  <thead>
    <tr>
      <th>Hostname</th>
      <th>Type</th>
      <th>OS</th>
      <th>Authorized</th>
      <th>Managed</th>
      <th>Source</th>
      <th>Last Seen</th>
    </tr>
  </thead>
  <tbody>
  {{range .Assets}}
    <tr>
      <td>{{.Hostname}}</td>
      <td>{{.AssetType}}</td>
      <td>{{.OSFamily}}{{if .OSVersion}} {{.OSVersion}}{{end}}</td>
      <td><span class="badge {{authClass .IsAuthorized}}">{{.IsAuthorized}}</span></td>
      <td>{{.IsManaged}}</td>
      <td>{{.DiscoverySource}}</td>
      <td>{{formatTime .LastSeenAt}}</td>
    </tr>
  {{end}}
  </tbody>
</table>`

const softwareTemplate = `<h2>Software ({{len .Software}})</h2>
<div class="table-actions">
  <a href="/api/v1/software/export.csv" class="btn">Export CSV</a>
</div>
<table>
  <thead>
    <tr>
      <th>Host</th>
      <th>Package</th>
      <th>Version</th>
      <th>Manager</th>
      <th>CPE 2.3</th>
    </tr>
  </thead>
  <tbody>
  {{range .Software}}
    <tr>
      <td>{{.Hostname}}</td>
      <td>{{.SoftwareName}}</td>
      <td>{{.Version}}</td>
      <td>{{.PackageManager}}</td>
      <td><code>{{.CPE23}}</code></td>
    </tr>
  {{end}}
  </tbody>
</table>`

const findingsTemplate = `<h2>Findings ({{len .Findings}})</h2>
<div class="table-actions">
  <a href="/api/v1/findings/export.csv" class="btn">Export CSV</a>
</div>
<table>
  <thead>
    <tr>
      <th>Check</th>
      <th>Severity</th>
      <th>CWE</th>
      <th>Title</th>
      <th>Auditor</th>
    </tr>
  </thead>
  <tbody>
  {{range .Findings}}
    <tr>
      <td>{{.CheckID}}</td>
      <td><span class="badge {{severityClass .Severity}}">{{.Severity}}</span></td>
      <td>{{.CWEID}}</td>
      <td>{{.Title}}</td>
      <td>{{.Auditor}}</td>
    </tr>
  {{end}}
  </tbody>
</table>`

const scansTemplate = `<h2>Scan History</h2>
<table>
  <thead>
    <tr>
      <th>Started</th>
      <th>Status</th>
      <th>Total Assets</th>
      <th>New</th>
      <th>Updated</th>
      <th>Stale</th>
      <th>Coverage</th>
    </tr>
  </thead>
  <tbody>
  {{range .Scans}}
    <tr>
      <td>{{formatTime .StartedAt}}</td>
      <td>{{.Status}}</td>
      <td>{{.TotalAssets}}</td>
      <td>{{.NewAssets}}</td>
      <td>{{.UpdatedAssets}}</td>
      <td>{{.StaleAssets}}</td>
      <td>{{printf "%.0f" .CoveragePercent}}%</td>
    </tr>
  {{end}}
  </tbody>
</table>`
