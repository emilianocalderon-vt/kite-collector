package vps

import (
	"context"
	"crypto/sha1" //#nosec G505 -- OVHcloud API requires SHA-1 signatures
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/safenet"
)

// OVHcloud implements discovery.Source for the OVHcloud API.
// It uses OVH's triple-auth scheme (app key + app secret + consumer key).
type OVHcloud struct {
	baseURL string
}

// NewOVHcloud returns a new OVHcloud discovery source.
func NewOVHcloud() *OVHcloud {
	return &OVHcloud{baseURL: ""}
}

// Name returns the stable identifier for this source.
func (o *OVHcloud) Name() string { return "ovhcloud" }

// Discover lists all OVHcloud dedicated servers and VPS.
// Credentials: KITE_OVHCLOUD_APP_KEY, KITE_OVHCLOUD_APP_SECRET,
// KITE_OVHCLOUD_CONSUMER_KEY environment variables.
// Region: KITE_OVHCLOUD_REGION ("eu" or "us", default "eu").
func (o *OVHcloud) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	appKey := os.Getenv("KITE_OVHCLOUD_APP_KEY")
	appSecret := os.Getenv("KITE_OVHCLOUD_APP_SECRET")
	consumerKey := os.Getenv("KITE_OVHCLOUD_CONSUMER_KEY")

	if appKey == "" || appSecret == "" || consumerKey == "" {
		if cfg != nil {
			return nil, fmt.Errorf("ovhcloud: KITE_OVHCLOUD_APP_KEY, KITE_OVHCLOUD_APP_SECRET, and KITE_OVHCLOUD_CONSUMER_KEY are required")
		}
		return nil, nil
	}

	region := os.Getenv("KITE_OVHCLOUD_REGION")
	if region == "" {
		region = "eu"
	}

	base := o.baseURL
	if base == "" {
		switch region {
		case "us":
			base = "https://api.us.ovhcloud.com/1.0"
		default:
			base = "https://eu.api.ovh.com/1.0"
		}
	}

	slog.Info("ovhcloud: starting discovery", "region", sanitizeLogValue(region)) //#nosec G706 -- control chars sanitized; operator-configured env var

	auth := ovhAuth(appKey, appSecret, consumerKey)
	client := newClient("ovhcloud", base, auth)

	var assets []model.Asset

	// Discover dedicated servers.
	dedicated, err := o.discoverDedicated(ctx, client, base, auth)
	if err != nil {
		slog.Warn("ovhcloud: dedicated server discovery failed", "error", err)
	} else {
		assets = append(assets, dedicated...)
	}

	// Discover VPS instances.
	vpsAssets, err := o.discoverVPS(ctx, client, base, auth)
	if err != nil {
		slog.Warn("ovhcloud: VPS discovery failed", "error", err)
	} else {
		assets = append(assets, vpsAssets...)
	}

	slog.Info("ovhcloud: discovery complete", "assets", len(assets))
	return assets, nil
}

func (o *OVHcloud) discoverDedicated(ctx context.Context, client *apiClient, base string, auth authFunc) ([]model.Asset, error) {
	var names []string
	if err := client.get(ctx, "/dedicated/server", &names); err != nil {
		return nil, fmt.Errorf("list dedicated servers: %w", err)
	}

	now := time.Now().UTC()
	var assets []model.Asset

	for _, name := range names {
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}

		safeName, sErr := safenet.SanitizePathSegment(name)
		if sErr != nil {
			slog.Warn("ovhcloud: skipping dedicated server with unsafe name", "name", sanitizeLogValue(name), "error", sErr)
			continue
		}

		var srv ovhDedicatedServer
		if err := client.get(ctx, "/dedicated/server/"+safeName, &srv); err != nil {
			slog.Warn("ovhcloud: get dedicated server failed", "name", safeName, "error", err)
			continue
		}
		assets = append(assets, ovhDedicatedToAsset(srv, now))
	}

	return assets, nil
}

func (o *OVHcloud) discoverVPS(ctx context.Context, client *apiClient, base string, auth authFunc) ([]model.Asset, error) {
	var names []string
	if err := client.get(ctx, "/vps", &names); err != nil {
		return nil, fmt.Errorf("list VPS: %w", err)
	}

	now := time.Now().UTC()
	var assets []model.Asset

	for _, name := range names {
		if ctx.Err() != nil {
			return assets, ctx.Err()
		}

		safeName, sErr := safenet.SanitizePathSegment(name)
		if sErr != nil {
			slog.Warn("ovhcloud: skipping VPS with unsafe name", "name", sanitizeLogValue(name), "error", sErr)
			continue
		}

		var instance ovhVPS
		if err := client.get(ctx, "/vps/"+safeName, &instance); err != nil {
			slog.Warn("ovhcloud: get VPS failed", "name", safeName, "error", err)
			continue
		}
		assets = append(assets, ovhVPSToAsset(instance, now))
	}

	return assets, nil
}

// --- OVH authentication ---

// ovhAuth returns an authFunc implementing OVH's triple-auth signature.
func ovhAuth(appKey, appSecret, consumerKey string) authFunc {
	return func(req *http.Request) {
		ts := fmt.Sprintf("%d", time.Now().Unix())
		body := ""
		url := req.URL.String()

		toSign := fmt.Sprintf("%s+%s+%s+%s+%s+%s",
			appSecret, consumerKey, req.Method, url, body, ts)

		h := sha1.New() //#nosec G401 -- OVHcloud API requires SHA-1 signatures
		h.Write([]byte(toSign))
		sig := "$1$" + hex.EncodeToString(h.Sum(nil))

		req.Header.Set("X-Ovh-Application", appKey)
		req.Header.Set("X-Ovh-Consumer", consumerKey)
		req.Header.Set("X-Ovh-Timestamp", ts)
		req.Header.Set("X-Ovh-Signature", sig)
	}
}

// --- OVH API response types ---

type ovhDedicatedServer struct {
	Name            string `json:"name"`
	IP              string `json:"ip"`
	OS              string `json:"os"`
	Reverse         string `json:"reverse"`
	Datacenter      string `json:"datacenter"`
	SupportLevel    string `json:"supportLevel"`
	CommercialRange string `json:"commercialRange"`
	State           string `json:"state"`
}

type ovhVPS struct {
	Name       string `json:"name"`
	DisplayName string `json:"displayName"`
	NetbootMode string `json:"netbootMode"`
	Model      ovhVPSModel `json:"model"`
	Zone       string      `json:"zone"`
	State      string      `json:"state"`
}

type ovhVPSModel struct {
	Name string `json:"name"`
}

// --- Asset mapping ---

func ovhDedicatedToAsset(srv ovhDedicatedServer, now time.Time) model.Asset {
	tags := map[string]any{
		"ip":               srv.IP,
		"reverse":          srv.Reverse,
		"commercial_range": srv.CommercialRange,
		"support_level":    srv.SupportLevel,
		"status":           srv.State,
	}
	if srv.State != "ok" {
		tags["warning"] = "server not in ok state"
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        srv.Name,
		AssetType:       model.AssetTypeServer,
		OSFamily:        srv.OS,
		Environment:     srv.Datacenter,
		DiscoverySource: "ovhcloud",
		FirstSeenAt:     now,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}

func ovhVPSToAsset(instance ovhVPS, now time.Time) model.Asset {
	hostname := instance.DisplayName
	if hostname == "" {
		hostname = instance.Name
	}

	tags := map[string]any{
		"model":  instance.Model.Name,
		"status": instance.State,
	}
	if instance.State != "running" {
		tags["warning"] = "VPS not running - not reachable by network scan"
	}

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        hostname,
		AssetType:       model.AssetTypeCloudInstance,
		Environment:     instance.Zone,
		DiscoverySource: "ovhcloud",
		FirstSeenAt:     now,
		LastSeenAt:      now,
		IsAuthorized:    model.AuthorizationUnknown,
		IsManaged:       model.ManagedUnknown,
		Tags:            toJSON(tags),
	}
	asset.ComputeNaturalKey()
	return asset
}
