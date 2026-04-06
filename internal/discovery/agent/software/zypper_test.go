// zypper_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseZypperOutput_ValidInput(t *testing.T) {
	raw := "S  | Name           | Type    | Version      | Arch   | Repository\n---+----------------+---------+--------------+--------+-----------\ni  | aaa_base       | package | 84.87        | x86_64 | Main\ni+ | bash           | package | 5.2.21-1.1   | x86_64 | Main\n"
	result := ParseZypperOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "aaa_base", result.Items[0].SoftwareName)
	assert.Equal(t, "84.87", result.Items[0].Version)
	assert.Equal(t, "x86_64", result.Items[0].Architecture)
	assert.Equal(t, "zypper", result.Items[0].PackageManager)
	assert.False(t, result.HasErrors())
}

func TestParseZypperOutput_EmptyInput(t *testing.T) {
	result := ParseZypperOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseZypperOutput_HeaderOnly(t *testing.T) {
	raw := "S  | Name           | Type    | Version      | Arch   | Repository\n---+----------------+---------+--------------+--------+-----------\n"
	result := ParseZypperOutput(raw)
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseZypperOutput_CPEHasArch(t *testing.T) {
	raw := "S  | Name | Type | Version | Arch | Repo\n---+------+------+---------+------+-----\ni  | curl | package | 8.7.1 | x86_64 | Main\n"
	result := ParseZypperOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:curl:8.7.1:*:*:*:*:*:x86_64:*", result.Items[0].CPE23)
}
