// dnf_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDnfOutput_ValidInput(t *testing.T) {
	raw := "acl.x86_64                       2.3.1-3.el9               @baseos\naudit.x86_64                     3.0.7-104.el9              @baseos\n"
	result := ParseDnfOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "acl", result.Items[0].SoftwareName)
	assert.Equal(t, "2.3.1-3.el9", result.Items[0].Version)
	assert.Equal(t, "x86_64", result.Items[0].Architecture)
	assert.Equal(t, "dnf", result.Items[0].PackageManager)
	assert.False(t, result.HasErrors())
}

func TestParseDnfOutput_EmptyInput(t *testing.T) {
	result := ParseDnfOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseDnfOutput_MalformedLine(t *testing.T) {
	result := ParseDnfOutput("badline\n")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "dnf", result.Errs[0].Collector)
}

func TestParseDnfOutput_CPEHasArch(t *testing.T) {
	raw := "curl.x86_64                      8.0.1-1.el9               @baseos\n"
	result := ParseDnfOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:curl:8.0.1-1.el9:*:*:*:*:*:x86_64:*", result.Items[0].CPE23)
}
