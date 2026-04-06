package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePipxJSON_ValidInput(t *testing.T) {
	raw := `{
		"venvs": {
			"black": {
				"metadata": {
					"main_package": {
						"package": "black",
						"package_version": "24.4.2"
					}
				}
			},
			"ruff": {
				"metadata": {
					"main_package": {
						"package": "ruff",
						"package_version": "0.4.8"
					}
				}
			}
		}
	}`
	result := ParsePipxJSON(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "pipx", result.Items[0].PackageManager)
	assert.Contains(t, result.Items[0].CPE23, "python")

	names := []string{result.Items[0].SoftwareName, result.Items[1].SoftwareName}
	assert.Contains(t, names, "black")
	assert.Contains(t, names, "ruff")
	assert.False(t, result.HasErrors())
}

func TestParsePipxJSON_EmptyInput(t *testing.T) {
	result := ParsePipxJSON("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParsePipxJSON_EmptyVenvs(t *testing.T) {
	result := ParsePipxJSON(`{"venvs": {}}`)
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParsePipxJSON_InvalidJSON_RecordsError(t *testing.T) {
	result := ParsePipxJSON("{bad")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "pipx", result.Errs[0].Collector)
}
