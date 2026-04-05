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

// Azure implements discovery.Source by listing virtual machines across one or
// more Azure regions within a subscription. It uses direct HTTP calls to the
// Azure Resource Manager REST API. Authentication is performed via OAuth2
// client credentials (service principal).
type Azure struct{}

// NewAzure returns a new Azure VM discovery source.
func NewAzure() *Azure {
	return &Azure{}
}

// Name returns the stable identifier for this source.
func (az *Azure) Name() string { return "azure_vm" }

// Discover lists Azure virtual machines in the configured subscription and
// regions, returning them as assets. Credentials are read from standard
// Azure environment variables. If credentials are not available the method
// logs a warning and returns nil (graceful degradation).
//
// Supported config keys:
//
//	regions         – []any of Azure region strings (e.g. ["eastus", "westeurope"])
//	subscription_id – string Azure subscription ID to enumerate VMs from
func (az *Azure) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	regions := toStringSlice(cfg["regions"])
	subscriptionID := toString(cfg["subscription_id"])

	slog.Info("azure_vm: starting discovery",
		"regions", regions,
		"subscription_id_set", subscriptionID != "",
	)

	creds := loadAzureCredentials()

	// Allow config to override the environment variable.
	if subscriptionID == "" {
		subscriptionID = creds.subscriptionID
	}

	if subscriptionID == "" {
		slog.Warn("azure_vm: no subscription_id in config or AZURE_SUBSCRIPTION_ID env, skipping discovery")
		return nil, nil
	}

	if creds.tenantID == "" || creds.clientID == "" || creds.clientSecret == "" {
		slog.Warn("azure_vm: AZURE_TENANT_ID, AZURE_CLIENT_ID, or AZURE_CLIENT_SECRET not set, skipping discovery")
		return nil, nil
	}

	token, err := az.acquireToken(ctx, creds)
	if err != nil {
		slog.Warn("azure_vm: failed to acquire OAuth2 token, skipping discovery",
			"error", err,
		)
		return nil, nil
	}

	vms, err := az.listVirtualMachines(ctx, subscriptionID, token)
	if err != nil {
		return nil, fmt.Errorf("azure_vm: listing VMs: %w", err)
	}

	// Build region filter set. An empty set means all regions are accepted.
	regionSet := make(map[string]bool, len(regions))
	for _, r := range regions {
		regionSet[strings.ToLower(r)] = true
	}

	now := time.Now().UTC()
	var assets []model.Asset

	for _, vm := range vms {
		if len(regionSet) > 0 && !regionSet[strings.ToLower(vm.location)] {
			continue
		}

		osFamily := deriveAzureOSFamily(vm)

		asset := model.Asset{
			ID:              uuid.Must(uuid.NewV7()),
			AssetType:       model.AssetTypeCloudInstance,
			Hostname:        vm.name,
			OSFamily:        osFamily,
			DiscoverySource: "azure_vm",
			FirstSeenAt:     now,
			LastSeenAt:      now,
			IsAuthorized:    model.AuthorizationUnknown,
			IsManaged:       model.ManagedUnknown,
			Environment:     vm.location,
		}
		asset.ComputeNaturalKey()
		assets = append(assets, asset)
	}

	slog.Info("azure_vm: discovery complete",
		"total_vms", len(vms),
		"matched_assets", len(assets),
	)
	return assets, nil
}

// ---------------------------------------------------------------------------
// Azure credentials
// ---------------------------------------------------------------------------

// azureCredentials holds Azure service principal authentication material
// read from the environment.
type azureCredentials struct {
	tenantID       string
	clientID       string
	clientSecret   string
	subscriptionID string
}

// loadAzureCredentials reads Azure credentials from standard environment
// variables.
func loadAzureCredentials() azureCredentials {
	return azureCredentials{
		tenantID:       os.Getenv("AZURE_TENANT_ID"),
		clientID:       os.Getenv("AZURE_CLIENT_ID"),
		clientSecret:   os.Getenv("AZURE_CLIENT_SECRET"),
		subscriptionID: os.Getenv("AZURE_SUBSCRIPTION_ID"),
	}
}

// ---------------------------------------------------------------------------
// Azure OAuth2 token acquisition
// ---------------------------------------------------------------------------

// acquireToken exchanges client credentials for an OAuth2 bearer token from
// the Microsoft identity platform (Azure AD v2.0 endpoint).
func (az *Azure) acquireToken(ctx context.Context, creds azureCredentials) (string, error) {
	tokenURL := fmt.Sprintf(
		"https://login.microsoftonline.com/%s/oauth2/v2.0/token",
		url.PathEscape(creds.tenantID),
	)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {creds.clientID},
		"client_secret": {creds.clientSecret},
		"scope":         {"https://management.azure.com/.default"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("executing token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %s",
			resp.StatusCode, truncateBytes(body, 300))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access_token in response")
	}

	return tokenResp.AccessToken, nil
}

// ---------------------------------------------------------------------------
// Azure Resource Manager API
// ---------------------------------------------------------------------------

const azureVMAPIVersion = "2024-07-01"

// azureVM holds the fields we extract from the ARM virtualMachines response.
type azureVM struct {
	name     string
	location string
	vmID     string
	osType   string // from storageProfile.osDisk.osType
	imageRef string // from storageProfile.imageReference.offer
}

// listVirtualMachines calls the ARM List All API to enumerate virtual machines
// across the entire subscription, handling pagination via nextLink.
func (az *Azure) listVirtualMachines(ctx context.Context, subscriptionID, token string) ([]azureVM, error) {
	apiURL := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/Microsoft.Compute/virtualMachines?api-version=%s",
		url.PathEscape(subscriptionID),
		azureVMAPIVersion,
	)

	var allVMs []azureVM

	for apiURL != "" {
		if ctx.Err() != nil {
			return allVMs, ctx.Err()
		}

		vms, nextLink, err := az.fetchVMPage(ctx, apiURL, token)
		if err != nil {
			return allVMs, err
		}
		allVMs = append(allVMs, vms...)
		apiURL = nextLink
	}

	return allVMs, nil
}

// fetchVMPage fetches a single page of the VM list response and returns
// parsed VMs plus the nextLink URL (empty if no more pages).
func (az *Azure) fetchVMPage(ctx context.Context, apiURL, token string) ([]azureVM, string, error) {
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
		return nil, "", fmt.Errorf("ARM API returned %d: %s",
			resp.StatusCode, truncateBytes(body, 500))
	}

	var result struct {
		NextLink string            `json:"nextLink"`
		Value    []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, "", fmt.Errorf("parsing response: %w", err)
	}

	var vms []azureVM
	for _, raw := range result.Value {
		vm, err := parseAzureVM(raw)
		if err != nil {
			slog.Debug("azure_vm: skipping unparseable VM entry", "error", err)
			continue
		}
		vms = append(vms, vm)
	}

	return vms, result.NextLink, nil
}

// parseAzureVM extracts the fields we need from a single VM JSON object.
func parseAzureVM(data json.RawMessage) (azureVM, error) {
	var raw struct {
		Name       string `json:"name"`
		Location   string `json:"location"`
		Properties struct {
			VMID           string `json:"vmId"`
			StorageProfile struct {
				OsDisk struct {
					OsType string `json:"osType"`
				} `json:"osDisk"`
				ImageReference struct {
					Offer     string `json:"offer"`
					Publisher string `json:"publisher"`
					Sku       string `json:"sku"`
				} `json:"imageReference"`
			} `json:"storageProfile"`
		} `json:"properties"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return azureVM{}, err
	}

	return azureVM{
		name:     raw.Name,
		location: raw.Location,
		vmID:     raw.Properties.VMID,
		osType:   raw.Properties.StorageProfile.OsDisk.OsType,
		imageRef: raw.Properties.StorageProfile.ImageReference.Offer,
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// deriveAzureOSFamily determines the OS family from the VM's storage profile.
func deriveAzureOSFamily(vm azureVM) string {
	// The osType field is the most reliable indicator.
	switch strings.ToLower(vm.osType) {
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	}

	// Fall back to image reference heuristics.
	offer := strings.ToLower(vm.imageRef)
	switch {
	case strings.Contains(offer, "windows"):
		return "windows"
	case strings.Contains(offer, "ubuntu"),
		strings.Contains(offer, "rhel"),
		strings.Contains(offer, "centos"),
		strings.Contains(offer, "debian"),
		strings.Contains(offer, "suse"),
		strings.Contains(offer, "oracle-linux"),
		strings.Contains(offer, "flatcar"),
		strings.Contains(offer, "coreweave"),
		strings.Contains(offer, "alma"),
		strings.Contains(offer, "rocky"):
		return "linux"
	}

	return "linux"
}

// ensure Azure satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*Azure)(nil)
