package cloud

import (
	"context"
	"log/slog"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// GCP implements discovery.Source by listing Compute Engine instances across
// one or more GCP regions within a project.
//
// This is a stub implementation that documents the expected configuration
// contract. A future version will integrate the Google Cloud Compute client
// library.
type GCP struct{}

// NewGCP returns a new GCP Compute Engine discovery source.
func NewGCP() *GCP {
	return &GCP{}
}

// Name returns the stable identifier for this source.
func (g *GCP) Name() string { return "gcp_compute" }

// Discover lists Compute Engine instances in the configured project and
// regions, returning them as assets. In the current stub implementation no
// cloud SDK calls are made.
//
// Supported config keys:
//
//	regions – []any of GCP region strings (e.g. ["us-central1", "europe-west1"])
//	project – string GCP project ID to enumerate instances from
func (g *GCP) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	regions := toStringSlice(cfg["regions"])
	project := toString(cfg["project"])

	slog.Info("gcp_compute: starting discovery",
		"regions", regions,
		"project", project,
	)

	slog.Info("gcp_compute: cloud discovery not yet implemented, requires cloud SDK")

	return nil, nil
}

// ensure GCP satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*GCP)(nil)
