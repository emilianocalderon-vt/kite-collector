package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNpmJSON_ValidInput(t *testing.T) {
	raw := `{"dependencies": {"typescript": {"version": "5.5.0"}, "npm": {"version": "10.8.1"}}}`
	result := ParseNpmJSON(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "npm", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "node.js")

	names := []string{result.Items[0].SoftwareName, result.Items[1].SoftwareName}
	assert.Contains(t, names, "typescript")
	assert.Contains(t, names, "npm")
	assert.False(t, result.HasErrors())
}

func TestParseNpmJSON_EmptyInput(t *testing.T) {
	result := ParseNpmJSON("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseNpmJSON_NoDependencies(t *testing.T) {
	result := ParseNpmJSON(`{"dependencies": {}}`)
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseNpmJSON_InvalidJSON_RecordsError(t *testing.T) {
	result := ParseNpmJSON("{bad")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "npm", result.Errs[0].Collector)
}

func TestParseNpmJSON_CPEHasTargetSW(t *testing.T) {
	raw := `{"dependencies": {"typescript": {"version": "5.5.0"}}}`
	result := ParseNpmJSON(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:typescript:5.5.0:*:*:*:*:node.js:*:*", result.Items[0].CPE23)
}
