package dashboard

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/vulnertrack/kite-collector/internal/store"
)

// Serve creates and returns an HTTP server for the dashboard.
// The caller is responsible for calling ListenAndServe.
func Serve(addr string, st store.Store, rc ReportContext, logger *slog.Logger) *http.Server {
	if logger == nil {
		logger = slog.Default()
	}

	mux := http.NewServeMux()

	// Serve static files (embedded or from disk in dev mode).
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		logger.Error("dashboard: failed to create sub filesystem", "error", err)
	} else {
		mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))
	}

	// Dashboard root — serves the main HTML page.
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		indexContent, readErr := fs.ReadFile(staticFS, "static/index.html")
		if readErr != nil {
			http.Error(w, "index.html not found", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(indexContent)
	})

	// renderFragment renders a template to a buffer first, then writes to
	// the response. This prevents "superfluous WriteHeader" when a template
	// error occurs after partial output has already been sent.
	renderFragment := func(w http.ResponseWriter, name string, render func(io.Writer) error) {
		var buf bytes.Buffer
		if renderErr := render(&buf); renderErr != nil {
			logger.Error("dashboard: render "+name, "error", renderErr)
			http.Error(w, renderErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(buf.Bytes())
	}

	// HTMX fragment endpoints — return HTML snippets for dynamic loading.
	mux.HandleFunc("GET /fragments/assets", func(w http.ResponseWriter, r *http.Request) {
		renderFragment(w, "assets", func(buf io.Writer) error {
			return renderAssetsFragment(buf, r.Context(), st, rc)
		})
	})

	mux.HandleFunc("GET /fragments/software", func(w http.ResponseWriter, r *http.Request) {
		renderFragment(w, "software", func(buf io.Writer) error {
			return renderSoftwareFragment(buf, r.Context(), st, rc)
		})
	})

	mux.HandleFunc("GET /fragments/findings", func(w http.ResponseWriter, r *http.Request) {
		renderFragment(w, "findings", func(buf io.Writer) error {
			return renderFindingsFragment(buf, r.Context(), st, rc)
		})
	})

	mux.HandleFunc("GET /fragments/scans", func(w http.ResponseWriter, r *http.Request) {
		renderFragment(w, "scans", func(buf io.Writer) error {
			return renderScansFragment(buf, r.Context(), st, rc)
		})
	})

	// CSV export endpoints.
	mux.HandleFunc("GET /api/v1/assets/export.csv", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=assets_%s.csv", rc.ReportID[:8]))
		if exportErr := exportAssetsCSV(w, r.Context(), st, rc); exportErr != nil {
			logger.Error("dashboard: export assets csv", "error", exportErr)
		}
	})

	mux.HandleFunc("GET /api/v1/software/export.csv", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=software_%s.csv", rc.ReportID[:8]))
		if exportErr := exportSoftwareCSV(w, r.Context(), st, rc); exportErr != nil {
			logger.Error("dashboard: export software csv", "error", exportErr)
		}
	})

	mux.HandleFunc("GET /api/v1/findings/export.csv", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=findings_%s.csv", rc.ReportID[:8]))
		if exportErr := exportFindingsCSV(w, r.Context(), st, rc); exportErr != nil {
			logger.Error("dashboard: export findings csv", "error", exportErr)
		}
	})

	// Scan trigger endpoint.
	mux.HandleFunc("POST /api/v1/scan", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<div class="badge badge-yellow">Scan triggered — refresh the page to see results.</div>`))
		logger.Info("dashboard: scan triggered via UI")
	})

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

// OpenBrowser attempts to open the given URL in the default browser.
// It uses platform-specific commands and silently ignores errors.
func OpenBrowser(url string) {
	openBrowser(url)
}

