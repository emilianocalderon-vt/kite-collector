package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseChocolateyOutput_ValidLines(t *testing.T) {
	raw := "Chocolatey v2.3.0\n7zip 24.08\ngit 2.45.2\nnotepadplusplus 8.6.9\n3 packages installed.\n"
	result := ParseChocolateyOutput(raw)

	require.Len(t, result.Items, 3)
	assert.Equal(t, "7zip", result.Items[0].SoftwareName)
	assert.Equal(t, "24.08", result.Items[0].Version)
	assert.Equal(t, "chocolatey", result.Items[0].PackageManager)
	assert.NotEmpty(t, result.Items[0].CPE23)

	assert.Equal(t, "git", result.Items[1].SoftwareName)
	assert.Equal(t, "2.45.2", result.Items[1].Version)

	assert.Equal(t, "notepadplusplus", result.Items[2].SoftwareName)
	assert.False(t, result.HasErrors())
}

func TestParseChocolateyOutput_EmptyInput(t *testing.T) {
	result := ParseChocolateyOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseChocolateyOutput_HeaderOnly(t *testing.T) {
	raw := "Chocolatey v2.3.0\n0 packages installed.\n"
	result := ParseChocolateyOutput(raw)

	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseChocolateyOutput_MalformedLine_RecordsError(t *testing.T) {
	raw := "Chocolatey v2.3.0\nnoversion\n1 packages installed.\n"
	result := ParseChocolateyOutput(raw)

	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "chocolatey", result.Errs[0].Collector)
}

func TestParseChocolateyOutput_MixedValidAndInvalid(t *testing.T) {
	raw := "Chocolatey v2.3.0\ngit 2.45.2\nbad\n7zip 24.08\n2 packages installed.\n"
	result := ParseChocolateyOutput(raw)

	require.Len(t, result.Items, 2)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "git", result.Items[0].SoftwareName)
	assert.Equal(t, "7zip", result.Items[1].SoftwareName)
}

func TestParseChocolateyOutput_SkipsBlankLines(t *testing.T) {
	raw := "Chocolatey v2.3.0\n\ngit 2.45.2\n\n1 packages installed.\n"
	result := ParseChocolateyOutput(raw)

	require.Len(t, result.Items, 1)
	assert.False(t, result.HasErrors())
}
