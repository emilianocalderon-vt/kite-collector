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

// CapRover implements discovery.Source for the CapRover REST API.
// CapRover is self-hosted, so the API endpoint is configurable.
type CapRover struct {
	baseURL string
}

// NewCapRover returns a new CapRover discovery source.
func NewCapRover() *CapRover {
	return &CapRover{}
}

// Name returns the stable identifier for this source.
func (cr *CapRover) Name() string { return "caprover" }

// Discover lists all CapRover app definitions.
// Credentials: KITE_CAPROVER_TOKEN environment variable.
// Endpoint: KITE_CAPROVER_ENDPOINT env var or "endpoint" config key.
func (cr *CapRover) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	token := os.Getenv("KITE_CAPROVER_TOKEN")
	endpoint := cr.baseURL

	if endpoint == "" {
		if cfg != nil {
			if e, ok := cfg["endpoint"].(string); ok && e != "" {
				endpoint = e
			}
		}
		if endpoint == "" {
			endpoint = os.Getenv("KITE_CAPROVER_ENDPOINT")
		}
	}

	if token == "" || endpoint == "" {
		if cfg != nil {
			if token == "" {
				return nil, fmt.Errorf("caprover: KITE_CAPROVER_TOKEN not set")
			}
			return nil, fmt.Errorf("caprover: endpoint not configured (set KITE_CAPROVER_ENDPOINT or config)")
		}
		return nil, nil
	}

	if cr.baseURL == "" {
		if _, err := safenet.ValidateEndpoint(endpoint, safenet.AllowPrivate()); err != nil {
			return nil, fmt.Errorf("caprover: %w", err)
		}
	}

	slog.Info("caprover: starting discovery", "endpoint", sanitizeLogValue(endpoint)) //#nosec G706 -- control chars sanitized; operator-configured env var

	tlsCfg, tlsErr := safenet.TLSConfig("KITE_CAPROVER_INSECURE", "KITE_CAPROVER_CA_CERT")
	if tlsErr != nil {
		return nil, fmt.Errorf("caprover: %w", tlsErr)
	}
	client := newClientWithTLS("caprover", endpoint, captainAuth(token), tlsCfg)

	var resp caproverAppsResponse
	if err := client.get(ctx, "/api/v2/user/apps/appDefinitions", &resp); err != nil {
		return nil, fmt.Errorf("caprover: list apps: %w", err)
	}

	if resp.Status != 100 {
		return nil, fmt.Errorf("caprover: unexpected API status %d: %s", resp.Status, resp.Description)
	}

	var assets []model.Asset
	now := time.Now().UTC()
	for i := range resp.Data.AppDefinitions {
		assets = append(assets, caproverToAsset(resp.Data.AppDefinitions[i], now))
	}

	slog.Info("caprover: discovery complete", "assets", len(assets))
	return assets, nil
}

// --- CapRover API response types ---

type caproverAppsResponse struct {
	Description string `json:"description"`
	Data        struct {
		AppDefinitions []caproverApp `json:"appDefinitions"`
	} `json:"data"`
	Status int `json:"status"`
}

type caproverApp struct {
	AppName           string `json:"appName"`
	InstanceCount     int    `json:"instanceCount"`
	HasPersistentData bool   `json:"hasPersistentData"`
	IsAppBuilding     bool   `json:"isAppBuilding"`
}

// --- Asset mapping ---

func caproverToAsset(app caproverApp, now time.Time) model.Asset {
	tags := map[string]any{
		"platform":        "caprover",
		"instance_count":  app.InstanceCount,
		"persistent_data": app.HasPersistentData,
	}
	if app.IsAppBuilding {
		tags["building"] = true
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        app.AppName,
		AssetType:       model.AssetTypeContainer,
		DiscoverySource: "caprover",
		FirstSeenAt:     now,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}
