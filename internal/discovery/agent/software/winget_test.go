package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWingetOutput_ValidLines(t *testing.T) {
	raw := "Name            Id                    Version   Available Source\n" +
		"-----------------------------------------------------------------------\n" +
		"Git             Git.Git               2.45.2              winget\n" +
		"Visual Studio   Microsoft.VS          17.10.0             winget\n"

	result := ParseWingetOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "Git", result.Items[0].SoftwareName)
	assert.Equal(t, "Git", result.Items[0].Vendor)
	assert.Equal(t, "2.45.2", result.Items[0].Version)
	assert.Equal(t, "winget", result.Items[0].PackageManager)
	assert.NotEmpty(t, result.Items[0].CPE23)

	assert.Equal(t, "Visual Studio", result.Items[1].SoftwareName)
	assert.Equal(t, "Microsoft", result.Items[1].Vendor)
	assert.Equal(t, "17.10.0", result.Items[1].Version)
}

func TestParseWingetOutput_EmptyInput(t *testing.T) {
	result := ParseWingetOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseWingetOutput_NoHeader(t *testing.T) {
	raw := "No packages found.\n"
	result := ParseWingetOutput(raw)

	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseWingetOutput_VendorExtraction(t *testing.T) {
	raw := "Name       Id                Version\n" +
		"--------------------------------------\n" +
		"Firefox    Mozilla.Firefox   127.0\n"

	result := ParseWingetOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "Mozilla", result.Items[0].Vendor)
	assert.Equal(t, "Firefox", result.Items[0].SoftwareName)
}

func TestParseWingetOutput_NoVendorDot(t *testing.T) {
	raw := "Name       Id          Version\n" +
		"-------------------------------\n" +
		"SomePkg    SomePkg     1.0\n"

	result := ParseWingetOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "", result.Items[0].Vendor)
}

func TestParseWingetOutput_SkipsBlankLines(t *testing.T) {
	raw := "Name       Id            Version\n" +
		"---------------------------------\n" +
		"Git        Git.Git       2.45.2\n" +
		"\n" +
		"Vim        Vim.Vim       9.1\n"

	result := ParseWingetOutput(raw)
	require.Len(t, result.Items, 2)
}

func TestParseWingetOutput_ShortLine_RecordsError(t *testing.T) {
	raw := "Name       Id            Version\n" +
		"---------------------------------\n" +
		"short\n"

	result := ParseWingetOutput(raw)

	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "winget", result.Errs[0].Collector)
}
