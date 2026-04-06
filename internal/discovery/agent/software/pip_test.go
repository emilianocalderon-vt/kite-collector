package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePipJSON_ValidInput(t *testing.T) {
	raw := `[{"name": "requests", "version": "2.31.0"}, {"name": "flask", "version": "3.0.3"}]`
	result := ParsePipJSON(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "requests", result.Items[0].SoftwareName)
	assert.Equal(t, "2.31.0", result.Items[0].Version)
	assert.Equal(t, "pip", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "python")

	assert.Equal(t, "flask", result.Items[1].SoftwareName)
	assert.False(t, result.HasErrors())
}

func TestParsePipJSON_EmptyInput(t *testing.T) {
	result := ParsePipJSON("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParsePipJSON_EmptyArray(t *testing.T) {
	result := ParsePipJSON("[]")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParsePipJSON_InvalidJSON_RecordsError(t *testing.T) {
	result := ParsePipJSON("{not json")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "pip", result.Errs[0].Collector)
}

func TestParsePipJSON_SkipsEmptyNames(t *testing.T) {
	raw := `[{"name": "", "version": "1.0"}, {"name": "valid", "version": "2.0"}]`
	result := ParsePipJSON(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "valid", result.Items[0].SoftwareName)
}

func TestParsePipJSON_CPEHasTargetSW(t *testing.T) {
	raw := `[{"name": "requests", "version": "2.31.0"}]`
	result := ParsePipJSON(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:requests:2.31.0:*:*:*:*:python:*:*", result.Items[0].CPE23)
}
