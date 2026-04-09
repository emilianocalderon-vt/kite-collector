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

// DigitalOcean implements discovery.Source for the DigitalOcean API.
type DigitalOcean struct {
	baseURL string
}

// NewDigitalOcean returns a new DigitalOcean discovery source.
func NewDigitalOcean() *DigitalOcean {
	return &DigitalOcean{baseURL: "https://api.digitalocean.com/v2"}
}

// Name returns the stable identifier for this source.
func (d *DigitalOcean) Name() string { return "digitalocean" }

// Discover lists all DigitalOcean droplets.
// Credentials: KITE_DIGITALOCEAN_TOKEN environment variable.
func (d *DigitalOcean) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	token := os.Getenv("KITE_DIGITALOCEAN_TOKEN")
	if token == "" {
		if cfg != nil {
			return nil, fmt.Errorf("digitalocean: KITE_DIGITALOCEAN_TOKEN not set")
		}
		return nil, nil
	}

	slog.Info("digitalocean: starting discovery")

	client := newClient("digitalocean", d.baseURL, bearerAuth(token))
	var assets []model.Asset
	guard := safenet.NewPaginationGuard()

	for page := 1; ; page++ {
		if err := guard.Next(); err != nil {
			return assets, fmt.Errorf("digitalocean: %w", err)
		}
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}

		var resp doDropletsResponse
		if err := client.get(ctx, fmt.Sprintf("/droplets?page=%d&per_page=100", page), &resp); err != nil {
			return assets, fmt.Errorf("digitalocean: list droplets: %w", err)
		}

		now := time.Now().UTC()
		for i := range resp.Droplets {
			assets = append(assets, doToAsset(resp.Droplets[i], now))
		}

		if resp.Links.Pages.Next == "" {
			break
		}
	}

	slog.Info("digitalocean: discovery complete", "assets", len(assets))
	return assets, nil
}

// --- DigitalOcean API response types ---

type doDropletsResponse struct {
	Links    doLinks     `json:"links"`
	Droplets []doDroplet `json:"droplets"`
}

type doLinks struct {
	Pages doPages `json:"pages"`
}

type doPages struct {
	Next string `json:"next"`
}

type doDroplet struct {
	Networks doNetworks `json:"networks"`
	Image    doImage    `json:"image"`
	Region   doRegion   `json:"region"`
	Name     string     `json:"name"`
	Status   string     `json:"status"`
	SizeSlug string     `json:"size_slug"`
	Created  string     `json:"created_at"`
	Tags     []string   `json:"tags"`
	ID       int        `json:"id"`
}

type doNetworks struct {
	V4 []doNetworkV4 `json:"v4"`
}

type doNetworkV4 struct {
	IPAddress string `json:"ip_address"`
	Type      string `json:"type"`
}

type doImage struct {
	Distribution string `json:"distribution"`
	Name         string `json:"name"`
}

type doRegion struct {
	Slug string `json:"slug"`
}

// --- Asset mapping ---

func doToAsset(drop doDroplet, now time.Time) model.Asset {
	ip := ""
	for _, n := range drop.Networks.V4 {
		if n.Type == "public" {
			ip = n.IPAddress
			break
		}
	}

	tags := map[string]any{
		"provider_id": drop.ID,
		"ip":          ip,
		"size":        drop.SizeSlug,
		"status":      drop.Status,
	}
	if len(drop.Tags) > 0 {
		tags["tags"] = drop.Tags
	}
	if drop.Status != "active" {
		tags["warning"] = "droplet not active - not reachable by network scan"
	}

	firstSeen := now
	if t, err := time.Parse(time.RFC3339, drop.Created); err == nil {
		firstSeen = t
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        drop.Name,
		AssetType:       model.AssetTypeCloudInstance,
		OSFamily:        drop.Image.Distribution,
		OSVersion:       drop.Image.Name,
		Environment:     drop.Region.Slug,
		DiscoverySource: "digitalocean",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}
