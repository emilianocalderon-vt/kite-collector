package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCargoOutput_ValidInput(t *testing.T) {
	raw := "cargo-edit v0.12.2:\n    cargo-add\n    cargo-rm\nripgrep v14.1.0:\n    rg\n"
	result := ParseCargoOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "cargo-edit", result.Items[0].SoftwareName)
	assert.Equal(t, "0.12.2", result.Items[0].Version)
	assert.Equal(t, "cargo", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "rust")

	assert.Equal(t, "ripgrep", result.Items[1].SoftwareName)
	assert.Equal(t, "14.1.0", result.Items[1].Version)
	assert.False(t, result.HasErrors())
}

func TestParseCargoOutput_EmptyInput(t *testing.T) {
	result := ParseCargoOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseCargoOutput_NoVPrefix(t *testing.T) {
	raw := "tool 1.0.0:\n    tool-bin\n"
	result := ParseCargoOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "tool", result.Items[0].SoftwareName)
	assert.Equal(t, "1.0.0", result.Items[0].Version)
}

func TestParseCargoOutput_MalformedLine_RecordsError(t *testing.T) {
	raw := "badline\n"
	result := ParseCargoOutput(raw)

	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "cargo", result.Errs[0].Collector)
}

func TestParseCargoOutput_CPEHasTargetSW(t *testing.T) {
	raw := "ripgrep v14.1.0:\n    rg\n"
	result := ParseCargoOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:ripgrep:14.1.0:*:*:*:*:rust:*:*", result.Items[0].CPE23)
}
