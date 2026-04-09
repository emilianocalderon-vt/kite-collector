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

// Heroku implements discovery.Source for the Heroku Platform API.
type Heroku struct {
	baseURL string
}

// NewHeroku returns a new Heroku discovery source.
func NewHeroku() *Heroku {
	return &Heroku{baseURL: "https://api.heroku.com"}
}

// Name returns the stable identifier for this source.
func (h *Heroku) Name() string { return "heroku" }

// Discover lists all Heroku apps using Range header pagination.
// Credentials: KITE_HEROKU_TOKEN environment variable.
func (h *Heroku) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	token := os.Getenv("KITE_HEROKU_TOKEN")
	if token == "" {
		if cfg != nil {
			return nil, fmt.Errorf("heroku: KITE_HEROKU_TOKEN not set")
		}
		return nil, nil
	}

	slog.Info("heroku: starting discovery")

	client := newClient("heroku", h.baseURL, bearerAuth(token))
	client.headers["Accept"] = "application/vnd.heroku+json; version=3"

	var assets []model.Asset
	rangeHeader := "id ..; max=200"
	guard := safenet.NewPaginationGuard()

	for {
		if err := guard.Next(); err != nil {
			return assets, fmt.Errorf("heroku: %w", err)
		}
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}

		var apps []herokuApp
		headers, err := client.getPage(ctx, "/apps", map[string]string{
			"Range": rangeHeader,
		}, &apps)
		if err != nil {
			return assets, fmt.Errorf("heroku: list apps: %w", err)
		}

		now := time.Now().UTC()
		for i := range apps {
			assets = append(assets, herokuToAsset(apps[i], now))
		}

		nextRange := headers.Get("Next-Range")
		if nextRange == "" {
			break
		}
		rangeHeader = nextRange
	}

	slog.Info("heroku: discovery complete", "assets", len(assets))
	return assets, nil
}

// --- Heroku API response types ---

type herokuApp struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	Stack                herokuRef `json:"stack"`
	Region               herokuRef `json:"region"`
	BuildpackDescription string    `json:"buildpack_provided_description"`
	WebURL               string    `json:"web_url"`
	ReleasedAt           string    `json:"released_at"`
	CreatedAt            string    `json:"created_at"`
	UpdatedAt            string    `json:"updated_at"`
	Maintenance          bool      `json:"maintenance"`
}

type herokuRef struct {
	Name string `json:"name"`
}

// --- Asset mapping ---

func herokuToAsset(app herokuApp, now time.Time) model.Asset {
	tags := map[string]any{
		"platform":    "heroku",
		"provider_id": app.ID,
		"stack":       app.Stack.Name,
		"url":         app.WebURL,
	}
	if app.BuildpackDescription != "" {
		tags["runtime"] = app.BuildpackDescription
	}
	if app.Maintenance {
		tags["maintenance"] = true
		tags["warning"] = "app in maintenance mode"
	}

	firstSeen := now
	if t, err := time.Parse(time.RFC3339, app.CreatedAt); err == nil {
		firstSeen = t
	}
	lastSeen := now
	if app.ReleasedAt != "" {
		if t, err := time.Parse(time.RFC3339, app.ReleasedAt); err == nil {
			lastSeen = t
		}
	} else if app.UpdatedAt != "" {
		if t, err := time.Parse(time.RFC3339, app.UpdatedAt); err == nil {
			lastSeen = t
		}
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        app.Name,
		AssetType:       model.AssetTypeContainer,
		Environment:     app.Region.Name,
		DiscoverySource: "heroku",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      lastSeen,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}
