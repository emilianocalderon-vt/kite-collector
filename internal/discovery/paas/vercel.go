package paas

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

const vercelPageSize = 100

// Vercel implements discovery.Source for the Vercel REST API.
type Vercel struct {
	baseURL string
}

// NewVercel returns a new Vercel discovery source.
func NewVercel() *Vercel {
	return &Vercel{baseURL: "https://api.vercel.com"}
}

// Name returns the stable identifier for this source.
func (v *Vercel) Name() string { return "vercel" }

// Discover lists all Vercel projects using timestamp-based pagination.
// Credentials: KITE_VERCEL_TOKEN environment variable.
func (v *Vercel) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	token := os.Getenv("KITE_VERCEL_TOKEN")
	if token == "" {
		if cfg != nil {
			return nil, fmt.Errorf("vercel: KITE_VERCEL_TOKEN not set")
		}
		return nil, nil
	}

	slog.Info("vercel: starting discovery")

	client := newClient("vercel", v.baseURL, bearerAuth(token))
	var assets []model.Asset
	var until string
	guard := safenet.NewPaginationGuard()

	for {
		if err := guard.Next(); err != nil {
			return assets, fmt.Errorf("vercel: %w", err)
		}
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}

		path := fmt.Sprintf("/v9/projects?limit=%d", vercelPageSize)
		if until != "" {
			path += "&until=" + until
		}

		var resp vercelProjectsResponse
		if err := client.get(ctx, path, &resp); err != nil {
			return assets, fmt.Errorf("vercel: list projects: %w", err)
		}

		now := time.Now().UTC()
		for i := range resp.Projects {
			assets = append(assets, vercelToAsset(resp.Projects[i], now))
		}

		if resp.Pagination.Next == nil {
			break
		}
		until = fmt.Sprintf("%d", *resp.Pagination.Next)
	}

	slog.Info("vercel: discovery complete", "assets", len(assets))
	return assets, nil
}

// --- Vercel API response types ---

type vercelProjectsResponse struct {
	Pagination vercelPagination `json:"pagination"`
	Projects   []vercelProject  `json:"projects"`
}

type vercelPagination struct {
	Next  *int64 `json:"next"`
	Count int    `json:"count"`
}

type vercelProject struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Framework string `json:"framework"`
	CreatedAt int64  `json:"createdAt"`
	UpdatedAt int64  `json:"updatedAt"`
}

// --- Asset mapping ---

func vercelToAsset(proj vercelProject, now time.Time) model.Asset {
	tags := map[string]any{
		"platform":    "vercel",
		"provider_id": proj.ID,
	}
	if proj.Framework != "" {
		tags["framework"] = proj.Framework
	}

	firstSeen := now
	if proj.CreatedAt > 0 {
		firstSeen = time.UnixMilli(proj.CreatedAt).UTC()
	}
	lastSeen := now
	if proj.UpdatedAt > 0 {
		lastSeen = time.UnixMilli(proj.UpdatedAt).UTC()
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        proj.Name,
		AssetType:       model.AssetTypeContainer,
		DiscoverySource: "vercel",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      lastSeen,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}
