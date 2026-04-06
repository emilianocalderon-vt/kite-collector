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

func TestRegionFromZone(t *testing.T) {
	tests := []struct {
		zone   string
		region string
	}{
		{"us-central1-a", "us-central1"},
		{"europe-west1-b", "europe-west1"},
		{"projects/my-project/zones/us-east1-c", "us-east1"},
		{"asia-southeast1-a", "asia-southeast1"},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.zone, func(t *testing.T) {
			assert.Equal(t, tc.region, regionFromZone(tc.zone))
		})
	}
}

func TestOSFromSourceImage(t *testing.T) {
	tests := []struct {
		sourceImage string
		expected    string
	}{
		{"projects/debian-cloud/global/images/debian-11-bullseye-v20230615", "linux"},
		{"projects/ubuntu-os-cloud/global/images/ubuntu-2204-jammy-v20231115", "linux"},
		{"projects/windows-cloud/global/images/windows-server-2022-dc-v20230615", "windows"},
		{"projects/cos-cloud/global/images/cos-stable-109-17800-0-0", "linux"},
		{"projects/rhel-cloud/global/images/rhel-9-v20231115", "linux"},
		{"projects/suse-cloud/global/images/sles-15-sp4-v20231115", "linux"},
		{"projects/rocky-linux-cloud/global/images/rocky-linux-9-v20231115", "linux"},
		{"projects/almalinux-cloud/global/images/almalinux-9-v20231115", "linux"},
		{"projects/fedora-cloud-devel/global/images/fedora-38-v20231115", "linux"},
		{"unknown-image", "linux"}, // default
		{"", "linux"},              // empty
	}

	for _, tc := range tests {
		t.Run(tc.sourceImage, func(t *testing.T) {
			assert.Equal(t, tc.expected, osFromSourceImage(tc.sourceImage))
		})
	}
}

func TestGuessOSFromDisks(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		disks    []gcpDisk
	}{
		{
			name:     "windows disk",
			disks:    []gcpDisk{{source: "projects/p/zones/z/disks/windows-server-2022"}},
			expected: "windows",
		},
		{
			name:     "ubuntu disk",
			disks:    []gcpDisk{{source: "projects/p/zones/z/disks/ubuntu-2204"}},
			expected: "linux",
		},
		{
			name:     "no disks",
			disks:    nil,
			expected: "linux",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, guessOSFromDisks(tc.disks))
		})
	}
}

func TestGCPDiscover_NoProject(t *testing.T) {
	gcp := NewGCP()
	assets, err := gcp.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Empty(t, assets, "should return nil when project is missing")
}

func TestFetchDiskSourceImage(t *testing.T) {
	diskJSON := `{"sourceImage":"projects/debian-cloud/global/images/debian-11-bullseye-v20230615"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(diskJSON))
	}))
	defer srv.Close()

	gcp := NewGCP()
	result := gcp.fetchDiskSourceImage(context.Background(), srv.URL, "fake-token")
	assert.Equal(t, "projects/debian-cloud/global/images/debian-11-bullseye-v20230615", result)
}

func TestFetchDiskSourceImage_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	gcp := NewGCP()
	result := gcp.fetchDiskSourceImage(context.Background(), srv.URL, "fake-token")
	assert.Empty(t, result, "should return empty on error")
}

func TestFetchInstancePage_Mock(t *testing.T) {
	response := map[string]any{
		"items": map[string]any{
			"zones/us-central1-a": map[string]any{
				"instances": []map[string]any{
					{
						"name": "vm-001",
						"zone": "projects/p/zones/us-central1-a",
						"disks": []map[string]any{
							{"source": "projects/p/zones/us-central1-a/disks/boot-001", "boot": true},
						},
					},
				},
			},
		},
		"nextPageToken": "",
	}

	respBytes, err := json.Marshal(response)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(respBytes)
	}))
	defer srv.Close()

	gcp := NewGCP()
	instances, nextURL, err := gcp.fetchInstancePage(context.Background(), srv.URL, "fake-token")
	require.NoError(t, err)
	assert.Empty(t, nextURL)
	require.Len(t, instances, 1)
	assert.Equal(t, "vm-001", instances[0].name)
	require.Len(t, instances[0].disks, 1)
	assert.True(t, instances[0].disks[0].boot)
}
