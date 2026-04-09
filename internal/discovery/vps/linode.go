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

// Linode implements discovery.Source for the Linode (Akamai) API v4.
type Linode struct {
	baseURL string
}

// NewLinode returns a new Linode discovery source.
func NewLinode() *Linode {
	return &Linode{baseURL: "https://api.linode.com/v4"}
}

// Name returns the stable identifier for this source.
func (l *Linode) Name() string { return "linode" }

// Discover lists all Linode instances.
// Credentials: KITE_LINODE_TOKEN environment variable.
func (l *Linode) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	token := os.Getenv("KITE_LINODE_TOKEN")
	if token == "" {
		if cfg != nil {
			return nil, fmt.Errorf("linode: KITE_LINODE_TOKEN not set")
		}
		return nil, nil
	}

	slog.Info("linode: starting discovery")

	client := newClient("linode", l.baseURL, bearerAuth(token))
	var assets []model.Asset
	guard := safenet.NewPaginationGuard()

	for page := 1; ; page++ {
		if err := guard.Next(); err != nil {
			return assets, fmt.Errorf("linode: %w", err)
		}
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}

		var resp linodeInstancesResponse
		if err := client.get(ctx, fmt.Sprintf("/linode/instances?page=%d&page_size=100", page), &resp); err != nil {
			return assets, fmt.Errorf("linode: list instances: %w", err)
		}

		now := time.Now().UTC()
		for i := range resp.Data {
			assets = append(assets, linodeToAsset(resp.Data[i], now))
		}

		if page >= resp.Pages {
			break
		}
	}

	slog.Info("linode: discovery complete", "assets", len(assets))
	return assets, nil
}

// --- Linode API response types ---

type linodeInstancesResponse struct {
	Data    []linodeInstance `json:"data"`
	Page    int              `json:"page"`
	Pages   int              `json:"pages"`
	Results int              `json:"results"`
}

type linodeInstance struct {
	Label   string        `json:"label"`
	Status  string        `json:"status"`
	Image   string        `json:"image"`
	Type    string        `json:"type"`
	Region  string        `json:"region"`
	Created string        `json:"created"`
	IPv4    []string      `json:"ipv4"`
	Tags    []string      `json:"tags"`
	Backups linodeBackups `json:"backups"`
	ID      int           `json:"id"`
}

type linodeBackups struct {
	LastSuccessful *string           `json:"last_successful"`
	Schedule       linodeBackupSched `json:"schedule"`
	Enabled        bool              `json:"enabled"`
}

type linodeBackupSched struct {
	Day    string `json:"day"`
	Window string `json:"window"`
}

// --- Asset mapping ---

func linodeToAsset(inst linodeInstance, now time.Time) model.Asset {
	ip := ""
	if len(inst.IPv4) > 0 {
		ip = inst.IPv4[0]
	}

	tags := map[string]any{
		"provider_id":     inst.ID,
		"ip":              ip,
		"type":            inst.Type,
		"status":          inst.Status,
		"backups_enabled": inst.Backups.Enabled,
	}
	if len(inst.Tags) > 0 {
		tags["tags"] = inst.Tags
	}
	if inst.Backups.LastSuccessful != nil {
		tags["last_backup"] = *inst.Backups.LastSuccessful
	}
	if inst.Status != "running" {
		tags["warning"] = "instance not running - not reachable by network scan"
	}

	firstSeen := now
	if t, err := time.Parse(time.RFC3339, inst.Created); err == nil {
		firstSeen = t
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        inst.Label,
		AssetType:       model.AssetTypeCloudInstance,
		OSFamily:        inst.Image,
		Environment:     inst.Region,
		DiscoverySource: "linode",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}
