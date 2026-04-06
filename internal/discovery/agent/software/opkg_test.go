// opkg_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOpkgOutput_ValidInput(t *testing.T) {
	raw := "base-files - 1627-r25099-32a3df073d\nbusybox - 1.36.1-1\n"
	result := ParseOpkgOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "base-files", result.Items[0].SoftwareName)
	assert.Equal(t, "1627-r25099-32a3df073d", result.Items[0].Version)
	assert.Equal(t, "opkg", result.Items[0].PackageManager)
	assert.False(t, result.HasErrors())
}

func TestParseOpkgOutput_EmptyInput(t *testing.T) {
	result := ParseOpkgOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseOpkgOutput_MalformedLine(t *testing.T) {
	result := ParseOpkgOutput("noseparator\n")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "opkg", result.Errs[0].Collector)
}

func TestParseOpkgOutput_CPE(t *testing.T) {
	raw := "curl - 8.7.1-1\n"
	result := ParseOpkgOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:curl:8.7.1-1:*:*:*:*:*:*:*", result.Items[0].CPE23)
}
