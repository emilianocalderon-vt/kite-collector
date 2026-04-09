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

// FlyIO implements discovery.Source for the Fly.io Machines API.
type FlyIO struct {
	baseURL string
}

// NewFlyIO returns a new Fly.io discovery source.
func NewFlyIO() *FlyIO {
	return &FlyIO{baseURL: "https://api.machines.dev"}
}

// Name returns the stable identifier for this source.
func (f *FlyIO) Name() string { return "flyio" }

// Discover lists all Fly.io machines across all apps in an organization.
// Credentials: KITE_FLY_TOKEN environment variable.
// Config: "org" key selects the organization slug (default "personal").
func (f *FlyIO) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	token := os.Getenv("KITE_FLY_TOKEN")
	if token == "" {
		if cfg != nil {
			return nil, fmt.Errorf("flyio: KITE_FLY_TOKEN not set")
		}
		return nil, nil
	}

	org := "personal"
	if cfg != nil {
		if o, ok := cfg["org"].(string); ok && o != "" {
			org = o
		}
	}

	slog.Info("flyio: starting discovery", "org", sanitizeLogValue(org))

	client := newClient("flyio", f.baseURL, bearerAuth(token))

	var appsResp flyAppsResponse
	if err := client.get(ctx, "/v1/apps?org_slug="+url.QueryEscape(org), &appsResp); err != nil {
		return nil, fmt.Errorf("flyio: list apps: %w", err)
	}

	var assets []model.Asset
	for _, app := range appsResp.Apps {
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}

		safeName, err := safenet.SanitizePathSegment(app.Name)
		if err != nil {
			slog.Warn("flyio: invalid app name, skipping",
				"app", sanitizeLogValue(app.Name),
				"error", err,
			)
			continue
		}

		var machines []flyMachine
		if err := client.get(ctx, "/v1/apps/"+safeName+"/machines", &machines); err != nil {
			slog.Warn("flyio: list machines failed, skipping app",
				"app", sanitizeLogValue(app.Name),
				"error", err,
			)
			continue
		}

		now := time.Now().UTC()
		for i := range machines {
			assets = append(assets, flyMachineToAsset(app.Name, machines[i], now))
		}
	}

	slog.Info("flyio: discovery complete", "assets", len(assets))
	return assets, nil
}

// --- Fly.io API response types ---

type flyAppsResponse struct {
	Apps      []flyApp `json:"apps"`
	TotalApps int      `json:"total_apps"`
}

type flyApp struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type flyMachine struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Region    string           `json:"region"`
	State     string           `json:"state"`
	CreatedAt string           `json:"created_at"`
	UpdatedAt string           `json:"updated_at"`
	Config    flyMachineConfig `json:"config"`
}

type flyMachineConfig struct {
	Image string          `json:"image"`
	Guest flyMachineGuest `json:"guest"`
}

type flyMachineGuest struct {
	CPUs     int `json:"cpus"`
	MemoryMB int `json:"memory_mb"`
}

// --- Asset mapping ---

func flyMachineToAsset(appName string, m flyMachine, now time.Time) model.Asset {
	hostname := m.Name
	if hostname == "" {
		hostname = m.ID
	}

	tags := map[string]any{
		"platform":    "flyio",
		"provider_id": m.ID,
		"app":         appName,
		"state":       m.State,
		"image":       m.Config.Image,
	}
	if m.Config.Guest.CPUs > 0 {
		tags["cpus"] = m.Config.Guest.CPUs
	}
	if m.Config.Guest.MemoryMB > 0 {
		tags["memory_mb"] = m.Config.Guest.MemoryMB
	}
	if m.State != "started" {
		tags["warning"] = fmt.Sprintf("machine state: %s", m.State)
	}

	firstSeen := now
	if t, err := time.Parse(time.RFC3339, m.CreatedAt); err == nil {
		firstSeen = t
	}
	lastSeen := now
	if t, err := time.Parse(time.RFC3339, m.UpdatedAt); err == nil {
		lastSeen = t
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        hostname,
		AssetType:       model.AssetTypeContainer,
		Environment:     m.Region,
		DiscoverySource: "flyio",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      lastSeen,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}
