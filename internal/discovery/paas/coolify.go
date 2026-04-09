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

// Coolify implements discovery.Source for the Coolify REST API.
// Coolify is self-hosted, so the API endpoint is configurable.
type Coolify struct {
	baseURL string
}

// NewCoolify returns a new Coolify discovery source.
func NewCoolify() *Coolify {
	return &Coolify{}
}

// Name returns the stable identifier for this source.
func (c *Coolify) Name() string { return "coolify" }

// Discover lists all Coolify applications and servers.
// Credentials: KITE_COOLIFY_TOKEN environment variable.
// Endpoint: KITE_COOLIFY_ENDPOINT env var or "endpoint" config key.
func (c *Coolify) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	token := os.Getenv("KITE_COOLIFY_TOKEN")
	endpoint := c.baseURL

	if endpoint == "" {
		if cfg != nil {
			if e, ok := cfg["endpoint"].(string); ok && e != "" {
				endpoint = e
			}
		}
		if endpoint == "" {
			endpoint = os.Getenv("KITE_COOLIFY_ENDPOINT")
		}
	}

	if token == "" || endpoint == "" {
		if cfg != nil {
			if token == "" {
				return nil, fmt.Errorf("coolify: KITE_COOLIFY_TOKEN not set")
			}
			return nil, fmt.Errorf("coolify: endpoint not configured (set KITE_COOLIFY_ENDPOINT or config)")
		}
		return nil, nil
	}

	if c.baseURL == "" {
		if _, err := safenet.ValidateEndpoint(endpoint, safenet.AllowPrivate()); err != nil {
			return nil, fmt.Errorf("coolify: %w", err)
		}
	}

	slog.Info("coolify: starting discovery", "endpoint", sanitizeLogValue(endpoint)) //#nosec G706 -- control chars sanitized; operator-configured env var

	tlsCfg, tlsErr := safenet.TLSConfig("KITE_COOLIFY_INSECURE", "KITE_COOLIFY_CA_CERT")
	if tlsErr != nil {
		return nil, fmt.Errorf("coolify: %w", tlsErr)
	}
	client := newClientWithTLS("coolify", endpoint, bearerAuth(token), tlsCfg)
	var assets []model.Asset
	now := time.Now().UTC()

	// Discover applications.
	var apps []coolifyApplication
	if err := client.get(ctx, "/api/v1/applications", &apps); err != nil {
		return nil, fmt.Errorf("coolify: list applications: %w", err)
	}
	for i := range apps {
		assets = append(assets, coolifyAppToAsset(apps[i], now))
	}

	// Discover servers.
	var servers []coolifyServer
	if err := client.get(ctx, "/api/v1/servers", &servers); err != nil {
		slog.Warn("coolify: list servers failed, continuing with apps only", "error", err)
	} else {
		for i := range servers {
			assets = append(assets, coolifyServerToAsset(servers[i], now))
		}
	}

	slog.Info("coolify: discovery complete", "assets", len(assets))
	return assets, nil
}

// --- Coolify API response types ---

type coolifyApplication struct {
	Name          string `json:"name"`
	FQDN          string `json:"fqdn"`
	Status        string `json:"status"`
	Description   string `json:"description"`
	GitRepository string `json:"git_repository"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
	ID            int    `json:"id"`
}

type coolifyServer struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	ID        int    `json:"id"`
}

// --- Asset mapping ---

func coolifyAppToAsset(app coolifyApplication, now time.Time) model.Asset {
	tags := map[string]any{
		"platform":    "coolify",
		"provider_id": app.ID,
	}
	if app.FQDN != "" {
		tags["fqdn"] = app.FQDN
	}
	if app.GitRepository != "" {
		tags["git_repository"] = app.GitRepository
	}
	if app.Status != "" {
		tags["status"] = app.Status
	}

	firstSeen := now
	if t, err := time.Parse(time.RFC3339, app.CreatedAt); err == nil {
		firstSeen = t
	}
	lastSeen := now
	if t, err := time.Parse(time.RFC3339, app.UpdatedAt); err == nil {
		lastSeen = t
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        app.Name,
		AssetType:       model.AssetTypeContainer,
		DiscoverySource: "coolify",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      lastSeen,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}

func coolifyServerToAsset(srv coolifyServer, now time.Time) model.Asset {
	tags := map[string]any{
		"platform":    "coolify",
		"provider_id": srv.ID,
	}
	if srv.IP != "" {
		tags["ip"] = srv.IP
	}
	if srv.Status != "" {
		tags["status"] = srv.Status
	}

	firstSeen := now
	if t, err := time.Parse(time.RFC3339, srv.CreatedAt); err == nil {
		firstSeen = t
	}
	lastSeen := now
	if t, err := time.Parse(time.RFC3339, srv.UpdatedAt); err == nil {
		lastSeen = t
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        srv.Name,
		AssetType:       model.AssetTypeServer,
		DiscoverySource: "coolify",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      lastSeen,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}
