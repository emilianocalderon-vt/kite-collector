// pkgsrc_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePkgsrcOutput_ValidInput(t *testing.T) {
	raw := "bash-5.2.21nb1     The GNU Bourne Again Shell\nvim-9.0.1678       Vim editor\n"
	result := ParsePkgsrcOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "bash", result.Items[0].SoftwareName)
	assert.Equal(t, "5.2.21nb1", result.Items[0].Version)
	assert.Equal(t, "pkgsrc", result.Items[0].PackageManager)
	assert.False(t, result.HasErrors())
}

func TestParsePkgsrcOutput_EmptyInput(t *testing.T) {
	result := ParsePkgsrcOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParsePkgsrcOutput_NoVersion(t *testing.T) {
	result := ParsePkgsrcOutput("nohyphendigit\n")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "pkgsrc", result.Errs[0].Collector)
}

func TestParsePkgsrcOutput_CPE(t *testing.T) {
	raw := "curl-8.7.1         Command line tool\n"
	result := ParsePkgsrcOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:curl:8.7.1:*:*:*:*:*:*:*", result.Items[0].CPE23)
}
