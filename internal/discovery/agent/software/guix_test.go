package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGuixOutput_ValidInput(t *testing.T) {
	raw := "python\t3.10.7\tout\t/gnu/store/...-python-3.10.7\nemacs\t29.1\tout\t/gnu/store/...-emacs-29.1\n"
	result := ParseGuixOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "python", result.Items[0].SoftwareName)
	assert.Equal(t, "3.10.7", result.Items[0].Version)
	assert.Equal(t, "guix", result.Items[0].PackageManager)
	assert.False(t, result.HasErrors())
}

func TestParseGuixOutput_EmptyInput(t *testing.T) {
	result := ParseGuixOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseGuixOutput_MalformedLine(t *testing.T) {
	result := ParseGuixOutput("notabseparated\n")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "guix", result.Errs[0].Collector)
}

func TestParseGuixOutput_CPE(t *testing.T) {
	raw := "emacs\t29.1\tout\t/gnu/store/...-emacs-29.1\n"
	result := ParseGuixOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:emacs:29.1:*:*:*:*:*:*:*", result.Items[0].CPE23)
}
