package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ParseAPKOutput
// ---------------------------------------------------------------------------

func TestParseAPKOutput_ValidLines(t *testing.T) {
	raw := "curl-8.7.1-r0 x86_64 {curl} (MIT)\nbusybox-1.36.1-r29 x86_64 {busybox} (GPL-2.0-only)\n"
	result := ParseAPKOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "curl", result.Items[0].SoftwareName)
	assert.Equal(t, "8.7.1-r0", result.Items[0].Version)
	assert.Equal(t, "curl", result.Items[0].Vendor)
	assert.Equal(t, "x86_64", result.Items[0].Architecture)
	assert.Equal(t, "apk", result.Items[0].PackageManager)
	assert.NotEmpty(t, result.Items[0].CPE23)

	assert.Equal(t, "busybox", result.Items[1].SoftwareName)
	assert.Equal(t, "1.36.1-r29", result.Items[1].Version)
	assert.Equal(t, "busybox", result.Items[1].Vendor)
	assert.False(t, result.HasErrors())
}

func TestParseAPKOutput_EmptyInput(t *testing.T) {
	result := ParseAPKOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseAPKOutput_MalformedLine_RecordsError(t *testing.T) {
	raw := "badline\n"
	result := ParseAPKOutput(raw)

	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "apk", result.Errs[0].Collector)
}

func TestParseAPKOutput_PackageWithHyphenatedName(t *testing.T) {
	raw := "alpine-base-3.20.0-r0 x86_64 {alpine-base} (MIT)\n"
	result := ParseAPKOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "alpine-base", result.Items[0].SoftwareName)
	assert.Equal(t, "3.20.0-r0", result.Items[0].Version)
	assert.Equal(t, "alpine-base", result.Items[0].Vendor)
}

func TestParseAPKOutput_NoOrigin(t *testing.T) {
	raw := "musl-1.2.5-r0 x86_64 (MIT)\n"
	result := ParseAPKOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "musl", result.Items[0].SoftwareName)
	assert.Equal(t, "", result.Items[0].Vendor)
}

func TestParseAPKOutput_SkipsWarningLines(t *testing.T) {
	raw := "WARNING: opening from cache\ncurl-8.7.1-r0 x86_64 {curl} (MIT)\n"
	result := ParseAPKOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "curl", result.Items[0].SoftwareName)
	assert.False(t, result.HasErrors())
}

func TestParseAPKOutput_MixedValidAndInvalid(t *testing.T) {
	raw := "curl-8.7.1-r0 x86_64 {curl} (MIT)\nnoversion\nbusybox-1.36.1-r29 x86_64 {busybox} (GPL-2.0-only)\n"
	result := ParseAPKOutput(raw)

	require.Len(t, result.Items, 2)
	require.Len(t, result.Errs, 1)
}

// ---------------------------------------------------------------------------
// splitNameVersion
// ---------------------------------------------------------------------------

func TestSplitNameVersion_Simple(t *testing.T) {
	name, version := splitNameVersion("curl-8.7.1-r0")
	assert.Equal(t, "curl", name)
	assert.Equal(t, "8.7.1-r0", version)
}

func TestSplitNameVersion_HyphenatedName(t *testing.T) {
	name, version := splitNameVersion("alpine-base-3.20.0-r0")
	assert.Equal(t, "alpine-base", name)
	assert.Equal(t, "3.20.0-r0", version)
}

func TestSplitNameVersion_NoVersion(t *testing.T) {
	name, version := splitNameVersion("curl")
	assert.Equal(t, "curl", name)
	assert.Equal(t, "", version)
}

func TestSplitNameVersion_StartsWithDigit(t *testing.T) {
	name, version := splitNameVersion("7zip-24.08")
	assert.Equal(t, "7zip", name)
	assert.Equal(t, "24.08", version)
}
