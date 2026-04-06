package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGemOutput_ValidLines(t *testing.T) {
	raw := "\n*** LOCAL GEMS ***\n\nbundler (2.5.11, default: 2.5.10)\nrake (13.2.1)\n"
	result := ParseGemOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "bundler", result.Items[0].SoftwareName)
	assert.Equal(t, "2.5.11", result.Items[0].Version)
	assert.Equal(t, "gem", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "ruby")

	assert.Equal(t, "rake", result.Items[1].SoftwareName)
	assert.Equal(t, "13.2.1", result.Items[1].Version)
	assert.False(t, result.HasErrors())
}

func TestParseGemOutput_EmptyInput(t *testing.T) {
	result := ParseGemOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseGemOutput_DefaultOnlyVersion(t *testing.T) {
	raw := "rdoc (default: 6.6.3.1)\n"
	result := ParseGemOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "rdoc", result.Items[0].SoftwareName)
	assert.Equal(t, "6.6.3.1", result.Items[0].Version)
}

func TestParseGemOutput_MalformedLine_RecordsError(t *testing.T) {
	raw := "badline\n"
	result := ParseGemOutput(raw)

	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "gem", result.Errs[0].Collector)
}

func TestParseGemOutput_MixedValidAndInvalid(t *testing.T) {
	raw := "rake (13.2.1)\nbad\nrspec (3.13.0)\n"
	result := ParseGemOutput(raw)

	require.Len(t, result.Items, 2)
	require.Len(t, result.Errs, 1)
}

func TestExtractFirstGemVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"2.5.11", "2.5.11"},
		{"2.5.11, default: 2.5.10", "2.5.11"},
		{"default: 6.6.3.1", "6.6.3.1"},
		{"", ""},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, extractFirstGemVersion(tt.input), "input: %s", tt.input)
	}
}
