package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFlatpakOutput_ValidLines(t *testing.T) {
	raw := "org.mozilla.firefox\t127.0\tflathub\n" +
		"org.gimp.GIMP\t2.10.38\tflathub\n"

	result := ParseFlatpakOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "firefox", result.Items[0].SoftwareName)
	assert.Equal(t, "mozilla", result.Items[0].Vendor)
	assert.Equal(t, "127.0", result.Items[0].Version)
	assert.Equal(t, "flatpak", result.Items[0].PackageManager)

	assert.Equal(t, "GIMP", result.Items[1].SoftwareName)
	assert.Equal(t, "gimp", result.Items[1].Vendor)
	assert.False(t, result.HasErrors())
}

func TestParseFlatpakOutput_EmptyInput(t *testing.T) {
	result := ParseFlatpakOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseFlatpakOutput_MalformedLine_RecordsError(t *testing.T) {
	raw := "badline\n"
	result := ParseFlatpakOutput(raw)

	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "flatpak", result.Errs[0].Collector)
}

func TestParseFlatpakOutput_TwoSegmentID(t *testing.T) {
	raw := "com.Slack\t4.39.0\tflathub\n"
	result := ParseFlatpakOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "Slack", result.Items[0].SoftwareName)
	assert.Equal(t, "com", result.Items[0].Vendor)
}

func TestParseFlatpakOutput_LongAppID(t *testing.T) {
	raw := "io.github.nickvdh.client\t1.0\tflathub\n"
	result := ParseFlatpakOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "client", result.Items[0].SoftwareName)
	assert.Equal(t, "github", result.Items[0].Vendor)
}

func TestParseFlatpakID(t *testing.T) {
	tests := []struct {
		input           string
		wantVendor      string
		wantProduct     string
	}{
		{"org.mozilla.firefox", "mozilla", "firefox"},
		{"org.gimp.GIMP", "gimp", "GIMP"},
		{"com.Slack", "com", "Slack"},
		{"singleword", "", "singleword"},
	}

	for _, tt := range tests {
		vendor, product := parseFlatpakID(tt.input)
		assert.Equal(t, tt.wantVendor, vendor, "vendor for %s", tt.input)
		assert.Equal(t, tt.wantProduct, product, "product for %s", tt.input)
	}
}
