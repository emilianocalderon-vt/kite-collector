package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSpackJSON_ValidInput(t *testing.T) {
	raw := `[{"name":"openmpi","version":"5.0.1"},{"name":"hdf5","version":"1.14.3"}]`
	result := ParseSpackJSON(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "openmpi", result.Items[0].SoftwareName)
	assert.Equal(t, "5.0.1", result.Items[0].Version)
	assert.Equal(t, "spack", result.Items[0].PackageManager)
	assert.False(t, result.HasErrors())
}

func TestParseSpackJSON_EmptyInput(t *testing.T) {
	result := ParseSpackJSON("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseSpackJSON_EmptyArray(t *testing.T) {
	result := ParseSpackJSON("[]")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseSpackJSON_InvalidJSON(t *testing.T) {
	result := ParseSpackJSON("{bad")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "spack", result.Errs[0].Collector)
}

func TestParseSpackJSON_CPE(t *testing.T) {
	raw := `[{"name":"openmpi","version":"5.0.1"}]`
	result := ParseSpackJSON(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:openmpi:5.0.1:*:*:*:*:*:*:*", result.Items[0].CPE23)
}
