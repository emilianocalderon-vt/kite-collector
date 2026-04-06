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

// UpCloud implements discovery.Source for the UpCloud API.
type UpCloud struct {
	baseURL string
}

// NewUpCloud returns a new UpCloud discovery source.
func NewUpCloud() *UpCloud {
	return &UpCloud{baseURL: "https://api.upcloud.com/1.3"}
}

// Name returns the stable identifier for this source.
func (u *UpCloud) Name() string { return "upcloud" }

// Discover lists all UpCloud servers.
// Credentials: KITE_UPCLOUD_USERNAME and KITE_UPCLOUD_PASSWORD env vars.
func (u *UpCloud) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	user := os.Getenv("KITE_UPCLOUD_USERNAME")
	pass := os.Getenv("KITE_UPCLOUD_PASSWORD")

	if user == "" || pass == "" {
		if cfg != nil {
			return nil, fmt.Errorf("upcloud: KITE_UPCLOUD_USERNAME and KITE_UPCLOUD_PASSWORD are required")
		}
		return nil, nil
	}

	slog.Info("upcloud: starting discovery")

	// UpCloud uses HTTP Basic authentication.
	client := newClient("upcloud", u.baseURL, basicAuth(user, pass))

	var resp upcloudServersResponse
	if err := client.get(ctx, "/server", &resp); err != nil {
		return nil, fmt.Errorf("upcloud: list servers: %w", err)
	}

	now := time.Now().UTC()
	assets := make([]model.Asset, 0, len(resp.Servers.Server))
	for i := range resp.Servers.Server {
		assets = append(assets, upcloudToAsset(resp.Servers.Server[i], now))
	}

	slog.Info("upcloud: discovery complete", "assets", len(assets))
	return assets, nil
}

// basicAuth returns an authFunc that sets HTTP Basic credentials.
func basicAuth(user, pass string) authFunc {
	return func(req *http.Request) {
		req.SetBasicAuth(user, pass)
	}
}

// --- UpCloud API response types ---

type upcloudServersResponse struct {
	Servers upcloudServerList `json:"servers"`
}

type upcloudServerList struct {
	Server []upcloudServer `json:"server"`
}

type upcloudServer struct {
	UUID        string              `json:"uuid"`
	Hostname    string              `json:"hostname"`
	State       string              `json:"state"`
	Plan        string              `json:"plan"`
	Zone        string              `json:"zone"`
	Title       string              `json:"title"`
	IPAddresses upcloudIPAddresses  `json:"ip_addresses"`
	Tags        upcloudTags         `json:"tags"`
}

type upcloudIPAddresses struct {
	IPAddress []upcloudIP `json:"ip_address"`
}

type upcloudIP struct {
	Address string `json:"address"`
	Access  string `json:"access"` // "public" or "private"
	Family  string `json:"family"` // "IPv4" or "IPv6"
}

type upcloudTags struct {
	Tag []string `json:"tag"`
}

// --- Asset mapping ---

func upcloudToAsset(srv upcloudServer, now time.Time) model.Asset {
	ip := ""
	for _, addr := range srv.IPAddresses.IPAddress {
		if addr.Access == "public" && addr.Family == "IPv4" {
			ip = addr.Address
			break
		}
	}

	tags := map[string]any{
		"provider_id": srv.UUID,
		"ip":          ip,
		"plan":        srv.Plan,
		"status":      srv.State,
	}
	if len(srv.Tags.Tag) > 0 {
		tags["tags"] = srv.Tags.Tag
	}
	if srv.State != "started" {
		tags["warning"] = "server not started - not reachable by network scan"
	}

	hostname := srv.Hostname
	if hostname == "" {
		hostname = srv.Title
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        hostname,
		AssetType:       model.AssetTypeCloudInstance,
		Environment:     srv.Zone,
		DiscoverySource: "upcloud",
		FirstSeenAt:     now,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}
