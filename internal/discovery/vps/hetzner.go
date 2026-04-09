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

// Hetzner implements discovery.Source for the Hetzner Cloud API.
type Hetzner struct {
	baseURL string // overridable in tests
}

// NewHetzner returns a new Hetzner discovery source.
func NewHetzner() *Hetzner {
	return &Hetzner{baseURL: "https://api.hetzner.cloud/v1"}
}

// Name returns the stable identifier for this source.
func (h *Hetzner) Name() string { return "hetzner" }

// Discover lists all Hetzner Cloud servers, including powered-off ones.
// Credentials: KITE_HETZNER_TOKEN environment variable.
func (h *Hetzner) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	token := os.Getenv("KITE_HETZNER_TOKEN")
	if token == "" {
		if cfg != nil {
			return nil, fmt.Errorf("hetzner: KITE_HETZNER_TOKEN not set")
		}
		return nil, nil
	}

	slog.Info("hetzner: starting discovery")

	client := newClient("hetzner", h.baseURL, bearerAuth(token))
	var assets []model.Asset
	guard := safenet.NewPaginationGuard()

	for page := 1; ; page++ {
		if err := guard.Next(); err != nil {
			return assets, fmt.Errorf("hetzner: %w", err)
		}
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}

		var resp hetznerServersResponse
		if err := client.get(ctx, fmt.Sprintf("/servers?page=%d&per_page=50", page), &resp); err != nil {
			return assets, fmt.Errorf("hetzner: list servers: %w", err)
		}

		now := time.Now().UTC()
		for i := range resp.Servers {
			assets = append(assets, hetznerToAsset(resp.Servers[i], now))
		}

		if resp.Meta.Pagination.NextPage == 0 {
			break
		}
	}

	slog.Info("hetzner: discovery complete", "assets", len(assets))
	return assets, nil
}

// --- Hetzner API response types ---

type hetznerServersResponse struct {
	Servers []hetznerServer `json:"servers"`
	Meta    hetznerMeta     `json:"meta"`
}

type hetznerMeta struct {
	Pagination hetznerPagination `json:"pagination"`
}

type hetznerPagination struct {
	NextPage     int `json:"next_page"`
	TotalEntries int `json:"total_entries"`
}

type hetznerServer struct {
	Image      *hetznerImage     `json:"image"`
	Labels     map[string]string `json:"labels"`
	PublicNet  hetznerPublicNet  `json:"public_net"`
	ServerType hetznerServerType `json:"server_type"`
	Datacenter hetznerDatacenter `json:"datacenter"`
	Name       string            `json:"name"`
	Status     string            `json:"status"`
	Created    string            `json:"created"`
	ID         int               `json:"id"`
}

type hetznerPublicNet struct {
	IPv4 hetznerIPv4 `json:"ipv4"`
}

type hetznerIPv4 struct {
	IP string `json:"ip"`
}

type hetznerServerType struct {
	Description string `json:"description"`
}

type hetznerDatacenter struct {
	Name string `json:"name"`
}

type hetznerImage struct {
	OSFlavor    string `json:"os_flavor"`
	Description string `json:"description"`
}

// --- Asset mapping ---

func hetznerToAsset(srv hetznerServer, now time.Time) model.Asset {
	tags := map[string]any{
		"provider_id": srv.ID,
		"ip":          srv.PublicNet.IPv4.IP,
		"server_type": srv.ServerType.Description,
		"status":      srv.Status,
	}
	if len(srv.Labels) > 0 {
		tags["labels"] = srv.Labels
	}
	if srv.Status != "running" {
		tags["warning"] = "server powered off - not reachable by network scan"
	}

	osFamily, osVersion := "", ""
	if srv.Image != nil {
		osFamily = srv.Image.OSFlavor
		osVersion = srv.Image.Description
	}

	firstSeen := now
	if t, err := time.Parse(time.RFC3339, srv.Created); err == nil {
		firstSeen = t
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        srv.Name,
		AssetType:       model.AssetTypeCloudInstance,
		OSFamily:        osFamily,
		OSVersion:       osVersion,
		Environment:     srv.Datacenter.Name,
		DiscoverySource: "hetzner",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}
