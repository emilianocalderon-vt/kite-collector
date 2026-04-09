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

// Vultr implements discovery.Source for the Vultr API v2.
type Vultr struct {
	baseURL string
}

// NewVultr returns a new Vultr discovery source.
func NewVultr() *Vultr {
	return &Vultr{baseURL: "https://api.vultr.com/v2"}
}

// Name returns the stable identifier for this source.
func (v *Vultr) Name() string { return "vultr" }

// Discover lists all Vultr instances using cursor-based pagination.
// Credentials: KITE_VULTR_TOKEN environment variable.
func (v *Vultr) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	token := os.Getenv("KITE_VULTR_TOKEN")
	if token == "" {
		if cfg != nil {
			return nil, fmt.Errorf("vultr: KITE_VULTR_TOKEN not set")
		}
		return nil, nil
	}

	slog.Info("vultr: starting discovery")

	client := newClient("vultr", v.baseURL, bearerAuth(token))
	var assets []model.Asset
	cursor := ""
	guard := safenet.NewPaginationGuard()

	for {
		if err := guard.Next(); err != nil {
			return assets, fmt.Errorf("vultr: %w", err)
		}
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}

		path := "/instances?per_page=100"
		if cursor != "" {
			path += "&cursor=" + cursor
		}

		var resp vultrInstancesResponse
		if err := client.get(ctx, path, &resp); err != nil {
			return assets, fmt.Errorf("vultr: list instances: %w", err)
		}

		now := time.Now().UTC()
		for i := range resp.Instances {
			assets = append(assets, vultrToAsset(resp.Instances[i], now))
		}

		cursor = resp.Meta.Links.Next
		if cursor == "" {
			break
		}
	}

	slog.Info("vultr: discovery complete", "assets", len(assets))
	return assets, nil
}

// --- Vultr API response types ---

type vultrInstancesResponse struct {
	Meta      vultrMeta      `json:"meta"`
	Instances []vultrInstance `json:"instances"`
}

type vultrMeta struct {
	Links vultrLinks `json:"links"`
	Total int        `json:"total"`
}

type vultrLinks struct {
	Next string `json:"next"`
	Prev string `json:"prev"`
}

type vultrInstance struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	OS          string   `json:"os"`
	Plan        string   `json:"plan"`
	Region      string   `json:"region"`
	Status      string   `json:"status"`
	MainIP      string   `json:"main_ip"`
	DateCreated string   `json:"date_created"`
	Tags        []string `json:"tags"`
}

// --- Asset mapping ---

func vultrToAsset(inst vultrInstance, now time.Time) model.Asset {
	tags := map[string]any{
		"provider_id": inst.ID,
		"ip":          inst.MainIP,
		"plan":        inst.Plan,
		"status":      inst.Status,
	}
	if len(inst.Tags) > 0 {
		tags["tags"] = inst.Tags
	}
	if inst.Status != "active" {
		tags["warning"] = "instance not active - not reachable by network scan"
	}

	firstSeen := now
	if t, err := time.Parse(time.RFC3339, inst.DateCreated); err == nil {
		firstSeen = t
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        inst.Label,
		AssetType:       model.AssetTypeCloudInstance,
		OSFamily:        inst.OS,
		Environment:     inst.Region,
		DiscoverySource: "vultr",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}
