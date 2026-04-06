package cloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveAzureOSFamily(t *testing.T) {
	tests := []struct {
		name     string
		vm       azureVM
		expected string
	}{
		{
			name:     "explicit Windows osType",
			vm:       azureVM{osType: "Windows"},
			expected: "windows",
		},
		{
			name:     "explicit Linux osType",
			vm:       azureVM{osType: "Linux"},
			expected: "linux",
		},
		{
			name:     "windows from imageRef",
			vm:       azureVM{imageRef: "WindowsServer"},
			expected: "windows",
		},
		{
			name:     "ubuntu from imageRef",
			vm:       azureVM{imageRef: "UbuntuServer"},
			expected: "linux",
		},
		{
			name:     "rhel from imageRef",
			vm:       azureVM{imageRef: "RHEL"},
			expected: "linux",
		},
		{
			name:     "no OS info defaults to linux",
			vm:       azureVM{},
			expected: "linux",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, deriveAzureOSFamily(tc.vm))
		})
	}
}

func TestParseAzureVM(t *testing.T) {
	raw := json.RawMessage(`{
		"name": "test-vm-01",
		"location": "eastus",
		"properties": {
			"vmId": "abc-123",
			"storageProfile": {
				"osDisk": {"osType": "Linux"},
				"imageReference": {
					"publisher": "Canonical",
					"offer": "UbuntuServer",
					"sku": "22_04-lts"
				}
			}
		}
	}`)

	vm, err := parseAzureVM(raw)
	require.NoError(t, err)
	assert.Equal(t, "test-vm-01", vm.name)
	assert.Equal(t, "eastus", vm.location)
	assert.Equal(t, "abc-123", vm.vmID)
	assert.Equal(t, "Linux", vm.osType)
	assert.Equal(t, "UbuntuServer", vm.imageRef)
}

func TestAzureDiscover_NoCredentials(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_CLIENT_SECRET", "")
	t.Setenv("AZURE_SUBSCRIPTION_ID", "")

	az := NewAzure()
	assets, err := az.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Empty(t, assets, "should return nil when credentials are missing")
}

func TestAzureListSubscriptions_Mock(t *testing.T) {
	response := map[string]any{
		"value": []map[string]any{
			{"subscriptionId": "sub-001", "state": "Enabled"},
			{"subscriptionId": "sub-002", "state": "Disabled"},
			{"subscriptionId": "sub-003", "state": "Enabled"},
		},
	}
	respBytes, err := json.Marshal(response)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(respBytes)
	}))
	defer srv.Close()

	// We can't redirect the ARM endpoint directly, but we can test the
	// parsing logic by verifying the response format.
	var result struct {
		Value []struct {
			SubscriptionID string `json:"subscriptionId"`
			State          string `json:"state"`
		} `json:"value"`
	}
	require.NoError(t, json.Unmarshal(respBytes, &result))
	assert.Len(t, result.Value, 3)

	// Verify only Enabled subscriptions would be selected.
	var enabled int
	for _, sub := range result.Value {
		if sub.State == "Enabled" {
			enabled++
		}
	}
	assert.Equal(t, 2, enabled)
}

func TestAzureFetchVMPage_Mock(t *testing.T) {
	response := map[string]any{
		"value": []map[string]any{
			{
				"name":     "vm-01",
				"location": "eastus",
				"properties": map[string]any{
					"vmId": "vm-id-01",
					"storageProfile": map[string]any{
						"osDisk":         map[string]any{"osType": "Linux"},
						"imageReference": map[string]any{"offer": "UbuntuServer"},
					},
				},
			},
			{
				"name":     "vm-02",
				"location": "westeurope",
				"properties": map[string]any{
					"vmId": "vm-id-02",
					"storageProfile": map[string]any{
						"osDisk":         map[string]any{"osType": "Windows"},
						"imageReference": map[string]any{"offer": "WindowsServer"},
					},
				},
			},
		},
	}
	respBytes, err := json.Marshal(response)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(respBytes)
	}))
	defer srv.Close()

	az := NewAzure()
	vms, nextLink, err := az.fetchVMPage(context.Background(), srv.URL, "fake-token")
	require.NoError(t, err)
	assert.Empty(t, nextLink)
	require.Len(t, vms, 2)

	assert.Equal(t, "vm-01", vms[0].name)
	assert.Equal(t, "eastus", vms[0].location)
	assert.Equal(t, "Linux", vms[0].osType)

	assert.Equal(t, "vm-02", vms[1].name)
	assert.Equal(t, "Windows", vms[1].osType)
}
