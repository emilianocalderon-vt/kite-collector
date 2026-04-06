package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseYayOutput_ValidLines(t *testing.T) {
	raw := "google-chrome 126.0.6478.126-1\nvisual-studio-code-bin 1.90.2-1\n"
	result := ParseYayOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "google-chrome", result.Items[0].SoftwareName)
	assert.Equal(t, "126.0.6478.126-1", result.Items[0].Version)
	assert.Equal(t, "yay", result.Items[0].PackageManager)

	assert.Equal(t, "visual-studio-code-bin", result.Items[1].SoftwareName)
	assert.Equal(t, "1.90.2-1", result.Items[1].Version)
	assert.False(t, result.HasErrors())
}

func TestParseYayOutput_EmptyInput(t *testing.T) {
	result := ParseYayOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseYayOutput_MalformedLine_RecordsError(t *testing.T) {
	raw := "noversion\n"
	result := ParseYayOutput(raw)

	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "yay", result.Errs[0].Collector)
}

func TestParseYayOutput_MixedValidAndInvalid(t *testing.T) {
	raw := "google-chrome 126.0.6478.126-1\nbad\nzoom 6.0.10.5765-1\n"
	result := ParseYayOutput(raw)

	require.Len(t, result.Items, 2)
	require.Len(t, result.Errs, 1)
}
