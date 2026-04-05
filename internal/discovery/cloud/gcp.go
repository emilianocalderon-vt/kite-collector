package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// GCP implements discovery.Source by listing Compute Engine instances across
// one or more GCP regions within a project. It uses direct HTTP calls to the
// Compute Engine REST API. Authentication is handled via the GCE metadata
// server (when running on GCE/GKE) or via an authorized_user refresh token
// from the application default credentials file.
type GCP struct{}

// NewGCP returns a new GCP Compute Engine discovery source.
func NewGCP() *GCP {
	return &GCP{}
}

// Name returns the stable identifier for this source.
func (g *GCP) Name() string { return "gcp_compute" }

// Discover lists Compute Engine instances in the configured project and
// regions, returning them as assets. If credentials are not available the
// method logs a warning and returns nil (graceful degradation).
//
// Supported config keys:
//
//	regions – []any of GCP region strings (e.g. ["us-central1", "europe-west1"])
//	project – string GCP project ID to enumerate instances from
func (g *GCP) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	regions := toStringSlice(cfg["regions"])
	project := toString(cfg["project"])

	slog.Info("gcp_compute: starting discovery",
		"regions", regions,
		"project", project,
	)

	if project == "" {
		slog.Warn("gcp_compute: project not specified in config, skipping discovery")
		return nil, nil
	}

	token, err := obtainGCPToken(ctx)
	if err != nil {
		slog.Warn("gcp_compute: could not obtain access token, skipping discovery",
			"error", err,
		)
		return nil, nil
	}

	instances, err := g.listAggregatedInstances(ctx, project, token)
	if err != nil {
		return nil, fmt.Errorf("gcp_compute: listing instances: %w", err)
	}

	// Build a set of desired regions for filtering. An empty set means all
	// regions are accepted.
	regionSet := make(map[string]bool, len(regions))
	for _, r := range regions {
		regionSet[r] = true
	}

	now := time.Now().UTC()
	var assets []model.Asset

	for _, inst := range instances {
		// Filter by region if regions were specified. The zone format is
		// "projects/{project}/zones/{region}-{zone-letter}", so we extract
		// the region portion.
		if len(regionSet) > 0 {
			instRegion := regionFromZone(inst.zone)
			if !regionSet[instRegion] {
				continue
			}
		}

		osFamily := guessOSFromDisks(inst.disks)

		asset := model.Asset{
			ID:              uuid.Must(uuid.NewV7()),
			AssetType:       model.AssetTypeCloudInstance,
			Hostname:        inst.name,
			OSFamily:        osFamily,
			DiscoverySource: "gcp_compute",
			FirstSeenAt:     now,
			LastSeenAt:      now,
			IsAuthorized:    model.AuthorizationUnknown,
			IsManaged:       model.ManagedUnknown,
			Environment:     inst.zone,
		}
		asset.ComputeNaturalKey()
		assets = append(assets, asset)
	}

	slog.Info("gcp_compute: discovery complete",
		"total_instances", len(instances),
		"matched_assets", len(assets),
	)
	return assets, nil
}

// ---------------------------------------------------------------------------
// GCP OAuth2 token acquisition
// ---------------------------------------------------------------------------

// obtainGCPToken tries to get a valid access token via the following methods
// in order:
//  1. GCE metadata server (works on Compute Engine, GKE, Cloud Run, etc.)
//  2. Application default credentials file (authorized_user with refresh token)
//
// Returns the bearer token string or an error.
func obtainGCPToken(ctx context.Context) (string, error) {
	// Attempt 1: GCE metadata server.
	token, err := tokenFromMetadata(ctx)
	if err == nil && token != "" {
		slog.Info("gcp_compute: obtained token from GCE metadata server")
		return token, nil
	}

	// Attempt 2: Application default credentials file.
	credFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credFile == "" {
		// Check the well-known default location.
		home, _ := os.UserHomeDir()
		if home != "" {
			credFile = home + "/.config/gcloud/application_default_credentials.json"
		}
	}
	if credFile != "" {
		token, err = tokenFromCredentialsFile(ctx, credFile)
		if err == nil && token != "" {
			slog.Info("gcp_compute: obtained token from credentials file")
			return token, nil
		}
		if err != nil {
			slog.Debug("gcp_compute: credentials file token exchange failed", //#nosec G706 -- error from internal file read, not user HTTP input
				"file", credFile,
				"error", err,
			)
		}
	}

	return "", fmt.Errorf("no GCP credentials available (tried metadata server and credentials file)")
}

// tokenFromMetadata queries the GCE metadata server for a default service
// account access token. This only works when running on GCE/GKE.
func tokenFromMetadata(ctx context.Context) (string, error) {
	metadataURL := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decoding metadata token: %w", err)
	}
	return tokenResp.AccessToken, nil
}

// tokenFromCredentialsFile reads an authorized_user or service_account
// credentials file and exchanges the refresh token for an access token.
// Only the authorized_user flow (refresh token exchange) is supported;
// service_account (JWT bearer) requires RSA signing which adds complexity.
func tokenFromCredentialsFile(ctx context.Context, path string) (string, error) {
	data, err := os.ReadFile(path) //#nosec G304 G703 -- path from trusted GOOGLE_APPLICATION_CREDENTIALS env var
	if err != nil {
		return "", fmt.Errorf("reading credentials file: %w", err)
	}

	var cred struct {
		Type         string `json:"type"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RefreshToken string `json:"refresh_token"`
	}
	if unmarshalErr := json.Unmarshal(data, &cred); unmarshalErr != nil {
		return "", fmt.Errorf("parsing credentials file: %w", unmarshalErr)
	}

	if cred.Type != "authorized_user" {
		return "", fmt.Errorf("unsupported credential type %q (only authorized_user refresh-token flow is supported without RSA)", cred.Type)
	}

	if cred.RefreshToken == "" || cred.ClientID == "" || cred.ClientSecret == "" {
		return "", fmt.Errorf("incomplete authorized_user credentials (missing refresh_token, client_id, or client_secret)")
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {cred.RefreshToken},
		"client_id":     {cred.ClientID},
		"client_secret": {cred.ClientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://oauth2.googleapis.com/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange returned %d: %s", resp.StatusCode, truncateBytes(body, 300))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}
	return tokenResp.AccessToken, nil
}

// ---------------------------------------------------------------------------
// Compute Engine API
// ---------------------------------------------------------------------------

// gcpInstance holds the fields we extract from the aggregated instances
// response.
type gcpInstance struct {
	name  string
	zone  string
	disks []gcpDisk
}

// gcpDisk holds minimal disk metadata for OS detection.
type gcpDisk struct {
	source string // source image URL
}

// listAggregatedInstances calls the Compute Engine aggregatedList API and
// returns all RUNNING instances across all zones.
func (g *GCP) listAggregatedInstances(ctx context.Context, project, token string) ([]gcpInstance, error) {
	apiURL := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/aggregated/instances?filter=status%%3DRUNNING&maxResults=500",
		url.PathEscape(project),
	)

	var allInstances []gcpInstance

	for apiURL != "" {
		if ctx.Err() != nil {
			return allInstances, ctx.Err()
		}

		instances, nextURL, err := g.fetchInstancePage(ctx, apiURL, token)
		if err != nil {
			return allInstances, err
		}
		allInstances = append(allInstances, instances...)
		apiURL = nextURL
	}

	return allInstances, nil
}

// fetchInstancePage fetches a single page of the aggregated instances
// response and returns parsed instances plus the next page URL (empty if
// no more pages).
func (g *GCP) fetchInstancePage(ctx context.Context, apiURL, token string) ([]gcpInstance, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("compute API returned %d: %s", resp.StatusCode, truncateBytes(body, 500))
	}

	var result struct {
		Items         map[string]json.RawMessage `json:"items"`
		NextPageToken string                     `json:"nextPageToken"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, "", fmt.Errorf("parsing response: %w", err)
	}

	var instances []gcpInstance
	for _, zoneData := range result.Items {
		var scopedList struct {
			Instances []struct {
				Name  string `json:"name"`
				Zone  string `json:"zone"`
				Disks []struct {
					Source string `json:"source"`
				} `json:"disks"`
			} `json:"instances"`
		}
		if err := json.Unmarshal(zoneData, &scopedList); err != nil {
			continue
		}
		for _, inst := range scopedList.Instances {
			gi := gcpInstance{
				name: inst.Name,
				zone: inst.Zone,
			}
			for _, d := range inst.Disks {
				gi.disks = append(gi.disks, gcpDisk{source: d.Source})
			}
			instances = append(instances, gi)
		}
	}

	// Build next page URL if there are more results.
	var nextURL string
	if result.NextPageToken != "" {
		u, err := url.Parse(apiURL)
		if err == nil {
			q := u.Query()
			q.Set("pageToken", result.NextPageToken)
			u.RawQuery = q.Encode()
			nextURL = u.String()
		}
	}

	return instances, nextURL, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// regionFromZone extracts the region from a GCP zone URL or zone name.
// Zone format: "projects/p/zones/us-central1-a" or just "us-central1-a".
// Region is everything except the last "-{letter}" suffix.
func regionFromZone(zone string) string {
	// Strip the resource URL prefix if present.
	if idx := strings.LastIndex(zone, "/"); idx >= 0 {
		zone = zone[idx+1:]
	}
	// Remove the trailing zone letter (e.g. "-a", "-b", "-f").
	if idx := strings.LastIndex(zone, "-"); idx > 0 {
		// Verify the suffix is a single character (zone letter).
		suffix := zone[idx+1:]
		if len(suffix) == 1 {
			return zone[:idx]
		}
	}
	return zone
}

// guessOSFromDisks inspects disk source image URLs for OS hints.
func guessOSFromDisks(disks []gcpDisk) string {
	for _, d := range disks {
		src := strings.ToLower(d.source)
		switch {
		case strings.Contains(src, "windows"):
			return "windows"
		case strings.Contains(src, "rhel"), strings.Contains(src, "red-hat"):
			return "linux"
		case strings.Contains(src, "centos"):
			return "linux"
		case strings.Contains(src, "debian"):
			return "linux"
		case strings.Contains(src, "ubuntu"):
			return "linux"
		case strings.Contains(src, "suse"), strings.Contains(src, "sles"):
			return "linux"
		case strings.Contains(src, "cos"), strings.Contains(src, "container-optimized"):
			return "linux"
		case strings.Contains(src, "fedora"):
			return "linux"
		case strings.Contains(src, "rocky"):
			return "linux"
		case strings.Contains(src, "alma"):
			return "linux"
		}
	}
	// Default assumption for GCE instances.
	return "linux"
}

// truncateBytes returns at most maxLen bytes from data as a string.
func truncateBytes(data []byte, maxLen int) string {
	if len(data) <= maxLen {
		return string(data)
	}
	return string(data[:maxLen]) + "..."
}

// ensure GCP satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*GCP)(nil)
