package vps

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safenet"
)

// Hostinger implements discovery.Source for the Hostinger VPS API.
type Hostinger struct {
	baseURL string
}

// NewHostinger returns a new Hostinger discovery source.
func NewHostinger() *Hostinger {
	return &Hostinger{baseURL: "https://developers.hostinger.com"}
}

// Name returns the stable identifier for this source.
func (h *Hostinger) Name() string { return "hostinger" }

// Discover lists all Hostinger VPS instances.
// Credentials: KITE_HOSTINGER_TOKEN environment variable.
func (h *Hostinger) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	token := os.Getenv("KITE_HOSTINGER_TOKEN")
	if token == "" {
		if cfg != nil {
			return nil, fmt.Errorf("hostinger: KITE_HOSTINGER_TOKEN not set")
		}
		return nil, nil
	}

	slog.Info("hostinger: starting discovery")

	client := newClient("hostinger", h.baseURL, bearerAuth(token))
	var assets []model.Asset
	guard := safenet.NewPaginationGuard()

	for page := 1; ; page++ {
		if err := guard.Next(); err != nil {
			return assets, fmt.Errorf("hostinger: %w", err)
		}
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}

		var resp hostingerVMsResponse
		if err := client.get(ctx, fmt.Sprintf("/api/vps/v1/virtual-machines?page=%d", page), &resp); err != nil {
			return assets, fmt.Errorf("hostinger: list VMs: %w", err)
		}

		now := time.Now().UTC()
		for i := range resp.Data {
			assets = append(assets, hostingerToAsset(resp.Data[i], now))
		}

		if resp.NextPage == "" {
			break
		}
	}

	slog.Info("hostinger: discovery complete", "assets", len(assets))
	return assets, nil
}

// --- Hostinger API response types ---

type hostingerVMsResponse struct {
	NextPage string        `json:"next_page_url"`
	Data     []hostingerVM `json:"data"`
}

type hostingerVM struct {
	Hostname   string `json:"hostname"`
	State      string `json:"state"`
	IPAddress  string `json:"ip_address"`
	OS         string `json:"os"`
	Datacenter string `json:"datacenter"`
	VCPU       int    `json:"vcpu"`
	RAM        int    `json:"ram_mb"`
	Disk       int    `json:"disk_gb"`
	ID         int    `json:"id"`
}

// --- Asset mapping ---

func hostingerToAsset(vm hostingerVM, now time.Time) model.Asset {
	tags := map[string]any{
		"provider_id": vm.ID,
		"ip":          vm.IPAddress,
		"vcpu":        vm.VCPU,
		"ram_mb":      vm.RAM,
		"disk_gb":     vm.Disk,
		"status":      vm.State,
	}
	if vm.State != "running" {
		tags["warning"] = "server powered off - not reachable by network scan"
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        vm.Hostname,
		AssetType:       model.AssetTypeCloudInstance,
		OSFamily:        vm.OS,
		Environment:     vm.Datacenter,
		DiscoverySource: "hostinger",
		FirstSeenAt:     now,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}
