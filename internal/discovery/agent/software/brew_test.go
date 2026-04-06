package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBrewOutput_ValidLines(t *testing.T) {
	raw := "curl 8.7.1\ngit 2.45.0\n"
	result := ParseBrewOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "curl", result.Items[0].SoftwareName)
	assert.Equal(t, "8.7.1", result.Items[0].Version)
	assert.Equal(t, "homebrew", result.Items[0].Vendor)
	assert.Equal(t, "brew", result.Items[0].PackageManager)
	assert.NotEmpty(t, result.Items[0].CPE23)
	assert.Contains(t, result.Items[0].CPE23, "homebrew")
	assert.Equal(t, "git", result.Items[1].SoftwareName)
	assert.False(t, result.HasErrors())
}

func TestParseBrewOutput_EmptyInput(t *testing.T) {
	result := ParseBrewOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseBrewOutput_MalformedLine_RecordsError(t *testing.T) {
	raw := "noversion\n"
	result := ParseBrewOutput(raw)

	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "brew", result.Errs[0].Collector)
	assert.Equal(t, 1, result.Errs[0].Line)
}

func TestParseBrewOutput_MultipleVersions_TakesFirst(t *testing.T) {
	raw := "python@3.12 3.12.4 3.12.3\n"
	result := ParseBrewOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "python@3.12", result.Items[0].SoftwareName)
	assert.Equal(t, "3.12.4", result.Items[0].Version)
}

func TestParseBrewOutput_MixedValidAndInvalid(t *testing.T) {
	raw := "curl 8.7.1\nbad\ngit 2.45.0\n"
	result := ParseBrewOutput(raw)

	require.Len(t, result.Items, 2)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "curl", result.Items[0].SoftwareName)
	assert.Equal(t, "git", result.Items[1].SoftwareName)
}

func TestParseBrewOutput_SkipsBlankLines(t *testing.T) {
	raw := "vim 9.0\n\nnano 7.2\n"
	result := ParseBrewOutput(raw)

	require.Len(t, result.Items, 2)
	assert.False(t, result.HasErrors())
}
