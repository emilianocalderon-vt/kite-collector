// xbps_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseXbpsOutput_ValidInput(t *testing.T) {
	raw := "ii xbps-0.59.2_1              XBPS package manager\nii bash-5.2.026_1             GNU Bourne Again Shell\n"
	result := ParseXbpsOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "xbps", result.Items[0].SoftwareName)
	assert.Equal(t, "0.59.2_1", result.Items[0].Version)
	assert.Equal(t, "xbps", result.Items[0].PackageManager)
	assert.False(t, result.HasErrors())
}

func TestParseXbpsOutput_EmptyInput(t *testing.T) {
	result := ParseXbpsOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseXbpsOutput_MalformedLine(t *testing.T) {
	result := ParseXbpsOutput("x\n")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "xbps", result.Errs[0].Collector)
}

func TestParseXbpsOutput_CPE(t *testing.T) {
	raw := "ii curl-8.7.1_1               Command line tool\n"
	result := ParseXbpsOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:curl:8.7.1_1:*:*:*:*:*:*:*", result.Items[0].CPE23)
}
