package metrics

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus instruments used by kite-collector.
// Each instance carries its own registry so nothing touches the global default.
type Metrics struct {
	ScanDuration    *prometheus.HistogramVec
	AssetsTotal     *prometheus.GaugeVec
	EventsEmitted   *prometheus.CounterVec
	DiscoveryErrors *prometheus.CounterVec
	ScanCoverage    *prometheus.GaugeVec
	StaleAssets     prometheus.Gauge
	DedupSkipped    prometheus.Counter
	PanicsRecovered        *prometheus.CounterVec
	CircuitBreakerTrips    *prometheus.CounterVec
	SourceHealth           *prometheus.GaugeVec
	ResponseTruncations    prometheus.Counter
	ScanDeadlineExceeded   prometheus.Counter
	registry               *prometheus.Registry
}

// New creates a Metrics instance backed by a private registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()

	scanDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "kite_scan_duration_seconds",
		Help: "Duration of discovery scans in seconds.",
	}, []string{"source"})

	assetsTotal := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kite_assets_total",
		Help: "Current number of known assets by type, authorization and managed state.",
	}, []string{"type", "authorized", "managed"})

	eventsEmitted := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kite_events_emitted_total",
		Help: "Total number of asset events emitted.",
	}, []string{"event_type"})

	discoveryErrors := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kite_discovery_errors_total",
		Help: "Total number of errors encountered during discovery.",
	}, []string{"source"})

	scanCoverage := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kite_scan_coverage_ratio",
		Help: "Fraction of expected assets that were seen in the latest scan.",
	}, []string{"source"})

	staleAssets := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "kite_stale_assets_total",
		Help: "Number of assets that have not been seen within the staleness threshold.",
	})

	dedupSkipped := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kite_dedup_skipped_total",
		Help: "Total number of duplicate assets skipped during deduplication.",
	})

	panicsRecovered := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kite_panics_recovered_total",
		Help: "Total number of panics caught by recovery middleware.",
	}, []string{"component"})

	circuitBreakerTrips := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kite_circuit_breaker_trips_total",
		Help: "Total number of circuit breaker trips per discovery source.",
	}, []string{"source"})

	sourceHealth := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kite_source_health",
		Help: "Discovery source health: 0=open, 0.5=degraded, 1=healthy.",
	}, []string{"source"})

	responseTruncations := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kite_response_truncations_total",
		Help: "Total number of HTTP responses truncated due to size limits.",
	})

	scanDeadlineExceeded := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kite_scan_deadline_exceeded_total",
		Help: "Total number of scans that exceeded the deadline.",
	})

	reg.MustRegister(
		scanDuration,
		assetsTotal,
		eventsEmitted,
		discoveryErrors,
		scanCoverage,
		staleAssets,
		dedupSkipped,
		panicsRecovered,
		circuitBreakerTrips,
		sourceHealth,
		responseTruncations,
		scanDeadlineExceeded,
	)

	return &Metrics{
		ScanDuration:         scanDuration,
		AssetsTotal:          assetsTotal,
		EventsEmitted:        eventsEmitted,
		DiscoveryErrors:      discoveryErrors,
		ScanCoverage:         scanCoverage,
		StaleAssets:          staleAssets,
		DedupSkipped:         dedupSkipped,
		PanicsRecovered:      panicsRecovered,
		CircuitBreakerTrips:  circuitBreakerTrips,
		SourceHealth:         sourceHealth,
		ResponseTruncations:  responseTruncations,
		ScanDeadlineExceeded: scanDeadlineExceeded,
		registry:             reg,
	}
}

// Handler returns an http.Handler that serves Prometheus metrics from the
// private registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Serve starts an HTTP server in a background goroutine that exposes
// /metrics on the given address. The returned *http.Server can be used
// to shut the listener down gracefully.
func (m *Metrics) Serve(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())

	slog.Info("starting metrics server", "addr", addr)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics server exited", "error", err)
		}
	}()

	return srv
}
