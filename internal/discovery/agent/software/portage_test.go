// portage_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePortageOutput_ValidInput(t *testing.T) {
	raw := "dev-libs/openssl-3.1.4-r1\nsys-apps/portage-2.3.99-r1\n"
	result := ParsePortageOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "openssl", result.Items[0].SoftwareName)
	assert.Equal(t, "3.1.4-r1", result.Items[0].Version)
	assert.Equal(t, "portage", result.Items[0].PackageManager)
	assert.False(t, result.HasErrors())
}

func TestParsePortageOutput_EmptyInput(t *testing.T) {
	result := ParsePortageOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParsePortageOutput_NoSlash(t *testing.T) {
	result := ParsePortageOutput("badline\n")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "portage", result.Errs[0].Collector)
}

func TestParsePortageOutput_CPE(t *testing.T) {
	raw := "dev-libs/openssl-3.1.4\n"
	result := ParsePortageOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:openssl:3.1.4:*:*:*:*:*:*:*", result.Items[0].CPE23)
}
