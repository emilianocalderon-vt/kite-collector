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
)

// Kamatera implements discovery.Source for the Kamatera API.
type Kamatera struct {
	baseURL string
}

// NewKamatera returns a new Kamatera discovery source.
func NewKamatera() *Kamatera {
	return &Kamatera{baseURL: "https://console.kamatera.com"}
}

// Name returns the stable identifier for this source.
func (k *Kamatera) Name() string { return "kamatera" }

// Discover lists all Kamatera servers.
// Credentials: KITE_KAMATERA_CLIENT_ID and KITE_KAMATERA_SECRET env vars.
func (k *Kamatera) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	clientID := os.Getenv("KITE_KAMATERA_CLIENT_ID")
	secret := os.Getenv("KITE_KAMATERA_SECRET")

	if clientID == "" || secret == "" {
		if cfg != nil {
			return nil, fmt.Errorf("kamatera: KITE_KAMATERA_CLIENT_ID and KITE_KAMATERA_SECRET are required")
		}
		return nil, nil
	}

	slog.Info("kamatera: starting discovery")

	client := newClient("kamatera", k.baseURL, func(req *http.Request) {
		req.Header.Set("AuthClientId", clientID)
		req.Header.Set("AuthSecret", secret)
	})

	var servers []kamateraServer
	if err := client.get(ctx, "/service/servers", &servers); err != nil {
		return nil, fmt.Errorf("kamatera: list servers: %w", err)
	}

	now := time.Now().UTC()
	assets := make([]model.Asset, 0, len(servers))
	for i := range servers {
		assets = append(assets, kamateraToAsset(servers[i], now))
	}

	slog.Info("kamatera: discovery complete", "assets", len(assets))
	return assets, nil
}

// --- Kamatera API response types ---

type kamateraServer struct {
	Name       string   `json:"name"`
	ID         string   `json:"id"`
	Datacenter string   `json:"datacenter"`
	Power      string   `json:"power"`
	CPU        string   `json:"cpu"`
	IPs        []string `json:"ips"`
	RAM        int      `json:"ram"`
}

// --- Asset mapping ---

func kamateraToAsset(srv kamateraServer, now time.Time) model.Asset {
	ip := ""
	if len(srv.IPs) > 0 {
		ip = srv.IPs[0]
	}

	tags := map[string]any{
		"provider_id": srv.ID,
		"ip":          ip,
		"cpu":         srv.CPU,
		"ram":         srv.RAM,
		"status":      srv.Power,
	}
	if srv.Power != "on" {
		tags["warning"] = "server powered off - not reachable by network scan"
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        srv.Name,
		AssetType:       model.AssetTypeCloudInstance,
		Environment:     srv.Datacenter,
		DiscoverySource: "kamatera",
		FirstSeenAt:     now,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}
