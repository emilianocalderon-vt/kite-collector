package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNixOutput_ValidLines(t *testing.T) {
	raw := "nix-2.18.1\ngit-2.45.0\n"
	result := ParseNixOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "nix", result.Items[0].SoftwareName)
	assert.Equal(t, "2.18.1", result.Items[0].Version)
	assert.Equal(t, "nix", result.Items[0].PackageManager)

	assert.Equal(t, "git", result.Items[1].SoftwareName)
	assert.Equal(t, "2.45.0", result.Items[1].Version)
	assert.False(t, result.HasErrors())
}

func TestParseNixOutput_EmptyInput(t *testing.T) {
	result := ParseNixOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseNixOutput_HyphenatedName(t *testing.T) {
	raw := "nixpkgs-fmt-1.3.0\n"
	result := ParseNixOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "nixpkgs-fmt", result.Items[0].SoftwareName)
	assert.Equal(t, "1.3.0", result.Items[0].Version)
}

func TestParseNixOutput_NoVersion_RecordsError(t *testing.T) {
	raw := "packageonly\n"
	result := ParseNixOutput(raw)

	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "nix", result.Errs[0].Collector)
}

func TestParseNixOutput_MixedValidAndInvalid(t *testing.T) {
	raw := "nix-2.18.1\nnoversion\ngit-2.45.0\n"
	result := ParseNixOutput(raw)

	require.Len(t, result.Items, 2)
	require.Len(t, result.Errs, 1)
}
