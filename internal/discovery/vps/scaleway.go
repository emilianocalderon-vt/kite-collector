package vps

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safenet"
)

// Scaleway implements discovery.Source for the Scaleway Instance API.
type Scaleway struct {
	baseURL string
}

// NewScaleway returns a new Scaleway discovery source.
func NewScaleway() *Scaleway {
	return &Scaleway{baseURL: "https://api.scaleway.com"}
}

// Name returns the stable identifier for this source.
func (s *Scaleway) Name() string { return "scaleway" }

// Discover lists all Scaleway instances in the configured zone.
// Credentials: KITE_SCALEWAY_SECRET_KEY environment variable.
// Zone: KITE_SCALEWAY_ZONE (default: fr-par-1).
func (s *Scaleway) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	token := os.Getenv("KITE_SCALEWAY_SECRET_KEY")
	if token == "" {
		if cfg != nil {
			return nil, fmt.Errorf("scaleway: KITE_SCALEWAY_SECRET_KEY not set")
		}
		return nil, nil
	}

	zone := os.Getenv("KITE_SCALEWAY_ZONE")
	if zone == "" {
		zone = "fr-par-1"
	}

	slog.Info("scaleway: starting discovery", "zone", sanitizeLogValue(zone)) //#nosec G706 -- control chars sanitized; operator-configured env var

	// Scaleway uses X-Auth-Token header instead of Authorization: Bearer.
	client := newClient("scaleway", s.baseURL, func(req *http.Request) {
		req.Header.Set("X-Auth-Token", token)
	})

	var assets []model.Asset
	guard := safenet.NewPaginationGuard()

	for page := 1; ; page++ {
		if err := guard.Next(); err != nil {
			return assets, fmt.Errorf("scaleway: %w", err)
		}
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}

		var resp scalewayServersResponse
		path := fmt.Sprintf("/instance/v1/zones/%s/servers?page=%d&per_page=100", zone, page)
		if err := client.get(ctx, path, &resp); err != nil {
			return assets, fmt.Errorf("scaleway: list servers: %w", err)
		}

		now := time.Now().UTC()
		for i := range resp.Servers {
			assets = append(assets, scalewayToAsset(resp.Servers[i], zone, now))
		}

		if len(resp.Servers) < 100 {
			break
		}
	}

	slog.Info("scaleway: discovery complete", "assets", len(assets)) //#nosec G706 -- integer count, no injection vector
	return assets, nil
}

// --- Scaleway API response types ---

type scalewayServersResponse struct {
	Servers []scalewayServer `json:"servers"`
}

type scalewayServer struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	State          string         `json:"state"`
	CommercialType string         `json:"commercial_type"`
	CreationDate   string         `json:"creation_date"`
	Image          *scalewayImage `json:"image"`
	PublicIPs      []scalewayIP   `json:"public_ips"`
	Tags           []string       `json:"tags"`
}

type scalewayImage struct {
	Name string `json:"name"`
}

type scalewayIP struct {
	Address string `json:"address"`
}

// --- Asset mapping ---

func scalewayToAsset(srv scalewayServer, zone string, now time.Time) model.Asset {
	ip := ""
	if len(srv.PublicIPs) > 0 {
		ip = srv.PublicIPs[0].Address
	}

	tags := map[string]any{
		"provider_id":     srv.ID,
		"ip":              ip,
		"commercial_type": srv.CommercialType,
		"status":          srv.State,
		"zone":            zone,
	}
	if len(srv.Tags) > 0 {
		tags["tags"] = srv.Tags
	}
	if srv.State != "running" {
		tags["warning"] = "server not running - not reachable by network scan"
	}

	osFamily := ""
	if srv.Image != nil {
		osFamily = srv.Image.Name
	}

	firstSeen := now
	if t, err := time.Parse(time.RFC3339, srv.CreationDate); err == nil {
		firstSeen = t
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        srv.Name,
		AssetType:       model.AssetTypeCloudInstance,
		OSFamily:        osFamily,
		Environment:     zone,
		DiscoverySource: "scaleway",
		FirstSeenAt:     firstSeen,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}
