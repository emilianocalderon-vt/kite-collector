// freebsdpkg_test.go
package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFreeBSDPkgOutput_ValidInput(t *testing.T) {
	raw := "curl-8.7.1                     Command line tool for transferring data\npkg-1.21.3                     Package manager\n"
	result := ParseFreeBSDPkgOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "curl", result.Items[0].SoftwareName)
	assert.Equal(t, "8.7.1", result.Items[0].Version)
	assert.Equal(t, "freebsdpkg", result.Items[0].PackageManager)
	assert.False(t, result.HasErrors())
}

func TestParseFreeBSDPkgOutput_EmptyInput(t *testing.T) {
	result := ParseFreeBSDPkgOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseFreeBSDPkgOutput_NoVersion(t *testing.T) {
	result := ParseFreeBSDPkgOutput("nohyphendigit\n")
	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "freebsdpkg", result.Errs[0].Collector)
}

func TestParseFreeBSDPkgOutput_CPE(t *testing.T) {
	raw := "openssl-3.3.0                  Secure sockets layer\n"
	result := ParseFreeBSDPkgOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "cpe:2.3:a:*:openssl:3.3.0:*:*:*:*:*:*:*", result.Items[0].CPE23)
}
