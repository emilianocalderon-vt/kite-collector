package cloud

import (
	"context"
	"log/slog"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Azure implements discovery.Source by listing virtual machines across one or
// more Azure regions within a subscription.
//
// This is a stub implementation that documents the expected configuration
// contract. A future version will integrate the Azure SDK for Go.
type Azure struct{}

// NewAzure returns a new Azure VM discovery source.
func NewAzure() *Azure {
	return &Azure{}
}

// Name returns the stable identifier for this source.
func (az *Azure) Name() string { return "azure_vm" }

// Discover lists Azure virtual machines in the configured subscription and
// regions, returning them as assets. In the current stub implementation no
// cloud SDK calls are made.
//
// Supported config keys:
//
//	regions         – []any of Azure region strings (e.g. ["eastus", "westeurope"])
//	subscription_id – string Azure subscription ID to enumerate VMs from
func (az *Azure) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	regions := toStringSlice(cfg["regions"])
	subscriptionID := toString(cfg["subscription_id"])

	slog.Info("azure_vm: starting discovery",
		"regions", regions,
		"subscription_id", subscriptionID,
	)

	slog.Info("azure_vm: cloud discovery not yet implemented, requires cloud SDK")

	return nil, nil
}

// ensure Azure satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*Azure)(nil)
