package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConanOutput_ValidInput(t *testing.T) {
	raw := "Local Cache\n  openssl\n    openssl/3.2.1\n      revisions\n  zlib\n    zlib/1.3.1\n      revisions\n"
	result := ParseConanOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "openssl", result.Items[0].SoftwareName)
	assert.Equal(t, "3.2.1", result.Items[0].Version)
	assert.Equal(t, "conan", result.Items[0].PackageManager)

	assert.Equal(t, "zlib", result.Items[1].SoftwareName)
	assert.Equal(t, "1.3.1", result.Items[1].Version)
	assert.False(t, result.HasErrors())
}

func TestParseConanOutput_EmptyInput(t *testing.T) {
	result := ParseConanOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseConanOutput_DeduplicatesPackages(t *testing.T) {
	raw := "  openssl/3.2.1\n  openssl/3.2.1\n"
	result := ParseConanOutput(raw)

	require.Len(t, result.Items, 1)
}

func TestParseConanOutput_WithAtSuffix(t *testing.T) {
	raw := "  openssl/3.2.1@_/_\n"
	result := ParseConanOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "3.2.1", result.Items[0].Version)
}

func TestParseConanOutput_CPEHasTargetSW(t *testing.T) {
	raw := "  openssl/3.2.1\n"
	result := ParseConanOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:openssl:3.2.1:*:*:*:*:cpp:*:*", result.Items[0].CPE23)
}
