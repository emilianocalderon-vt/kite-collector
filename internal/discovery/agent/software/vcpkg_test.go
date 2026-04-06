package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVcpkgOutput_ValidInput(t *testing.T) {
	raw := "curl:x64-linux                            8.7.1                curl is a tool\nopenssl:x64-linux                         3.3.0#1              TLS library\n"
	result := ParseVcpkgOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "curl", result.Items[0].SoftwareName)
	assert.Equal(t, "8.7.1", result.Items[0].Version)
	assert.Equal(t, "x64-linux", result.Items[0].Architecture)
	assert.Equal(t, "vcpkg", result.Items[0].PackageManager)
	assert.False(t, result.HasErrors())

	assert.Equal(t, "openssl", result.Items[1].SoftwareName)
	assert.Equal(t, "3.3.0", result.Items[1].Version)
}

func TestParseVcpkgOutput_EmptyInput(t *testing.T) {
	result := ParseVcpkgOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseVcpkgOutput_MalformedLine(t *testing.T) {
	result := ParseVcpkgOutput("badline\n")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "vcpkg", result.Errs[0].Collector)
}

func TestParseVcpkgOutput_CPEHasTargetSW(t *testing.T) {
	raw := "openssl:x64-linux  3.3.0  TLS\n"
	result := ParseVcpkgOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:openssl:3.3.0:*:*:*:*:cpp:*:*", result.Items[0].CPE23)
}
