// macports_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMacPortsOutput_ValidInput(t *testing.T) {
	raw := "The following ports are currently installed:\n  autoconf @2.72_0 (active)\n  cmake @3.29.3_0+docs (active)\n"
	result := ParseMacPortsOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "autoconf", result.Items[0].SoftwareName)
	assert.Equal(t, "2.72", result.Items[0].Version)
	assert.Equal(t, "macports", result.Items[0].PackageManager)
	assert.Equal(t, "macports", result.Items[0].Vendor)
	assert.False(t, result.HasErrors())
}

func TestParseMacPortsOutput_EmptyInput(t *testing.T) {
	result := ParseMacPortsOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseMacPortsOutput_HeaderOnly(t *testing.T) {
	result := ParseMacPortsOutput("The following ports are currently installed:\n")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseMacPortsOutput_CPE(t *testing.T) {
	raw := "The following ports are currently installed:\n  curl @8.7.1_0 (active)\n"
	result := ParseMacPortsOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:macports:curl:8.7.1:*:*:*:*:*:*:*", result.Items[0].CPE23)
}
