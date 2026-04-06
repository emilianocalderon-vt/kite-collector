package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePnpmJSON_ValidInput(t *testing.T) {
	raw := `[{"dependencies": {"typescript": {"version": "5.5.0"}, "eslint": {"version": "9.5.0"}}}]`
	result := ParsePnpmJSON(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "pnpm", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "node.js")

	names := []string{result.Items[0].SoftwareName, result.Items[1].SoftwareName}
	assert.Contains(t, names, "typescript")
	assert.Contains(t, names, "eslint")
	assert.False(t, result.HasErrors())
}

func TestParsePnpmJSON_EmptyInput(t *testing.T) {
	result := ParsePnpmJSON("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParsePnpmJSON_EmptyArray(t *testing.T) {
	result := ParsePnpmJSON("[]")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParsePnpmJSON_InvalidJSON_RecordsError(t *testing.T) {
	result := ParsePnpmJSON("{bad")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "pnpm", result.Errs[0].Collector)
}
