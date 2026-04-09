package paas

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safenet"
)

const renderPageSize = 100

// Render implements discovery.Source for the Render REST API.
type Render struct {
	baseURL string
}

// NewRender returns a new Render discovery source.
func NewRender() *Render {
	return &Render{baseURL: "https://api.render.com"}
}

// Name returns the stable identifier for this source.
func (r *Render) Name() string { return "render" }

// Discover lists all Render services using cursor-based pagination.
// Credentials: KITE_RENDER_TOKEN environment variable.
func (r *Render) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	token := os.Getenv("KITE_RENDER_TOKEN")
	if token == "" {
		if cfg != nil {
			return nil, fmt.Errorf("render: KITE_RENDER_TOKEN not set")
		}
		return nil, nil
	}

	slog.Info("render: starting discovery")

	client := newClient("render", r.baseURL, bearerAuth(token))
	var assets []model.Asset
	cursor := ""
	guard := safenet.NewPaginationGuard()

	for {
		if err := guard.Next(); err != nil {
			return assets, fmt.Errorf("render: %w", err)
		}
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}

		path := fmt.Sprintf("/v1/services?limit=%d", renderPageSize)
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}

		var wrappers []renderServiceWrapper
		if err := client.get(ctx, path, &wrappers); err != nil {
			return assets, fmt.Errorf("render: list services: %w", err)
		}

		if len(wrappers) == 0 {
			break
		}

		now := time.Now().UTC()
		for i := range wrappers {
			assets = append(assets, renderToAsset(wrappers[i].Service, now))
		}

		cursor = wrappers[len(wrappers)-1].Cursor
	}

	slog.Info("render: discovery complete", "assets", len(assets))
	return assets, nil
}

// --- Render API response types ---

type renderServiceWrapper struct {
	Service renderService `json:"service"`
	Cursor  string        `json:"cursor"`
}

type renderService struct {
	ID             string               `json:"id"`
	Name           string               `json:"name"`
	Type           string               `json:"type"`
	Suspended      string               `json:"suspended"`
	ServiceDetails renderServiceDetails `json:"serviceDetails"`
	CreatedAt      string               `json:"createdAt"`
	UpdatedAt      string               `json:"updatedAt"`
}

type renderServiceDetails struct {
	Runtime string `json:"runtime"`
	Region  string `json:"region"`
}

// --- Asset mapping ---

func renderToAsset(svc renderService, now time.Time) model.Asset {
	tags := map[string]any{
		"platform":    "render",
		"provider_id": svc.ID,
		"type":        svc.Type,
	}
	if svc.ServiceDetails.Runtime != "" {
		tags["runtime"] = svc.ServiceDetails.Runtime
	}
	if svc.Suspended == "suspended" {
		tags["suspended"] = true
		tags["warning"] = "service is suspended"
	}

	firstSeen := now
	if t, err := time.Parse(time.RFC3339Nano, svc.CreatedAt); err == nil {
		firstSeen = t
	}
	lastSeen := now
	if t, err := time.Parse(time.RFC3339Nano, svc.UpdatedAt); err == nil {
		lastSeen = t
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        svc.Name,
		AssetType:       model.AssetTypeContainer,
		Environment:     svc.ServiceDetails.Region,
		DiscoverySource: "render",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      lastSeen,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}
