package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSnapOutput_ValidLines(t *testing.T) {
	raw := "Name      Version    Rev    Tracking       Publisher   Notes\n" +
		"code      1.90.0     155    latest/stable  vscode\u2713     classic\n" +
		"firefox   127.0      4090   latest/stable  mozilla\u2713    -\n"

	result := ParseSnapOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "code", result.Items[0].SoftwareName)
	assert.Equal(t, "1.90.0", result.Items[0].Version)
	assert.Equal(t, "vscode", result.Items[0].Vendor)
	assert.Equal(t, "snap", result.Items[0].PackageManager)

	assert.Equal(t, "firefox", result.Items[1].SoftwareName)
	assert.Equal(t, "mozilla", result.Items[1].Vendor)
	assert.False(t, result.HasErrors())
}

func TestParseSnapOutput_EmptyInput(t *testing.T) {
	result := ParseSnapOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseSnapOutput_HeaderOnly(t *testing.T) {
	raw := "Name      Version    Rev    Tracking       Publisher   Notes\n"
	result := ParseSnapOutput(raw)

	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseSnapOutput_MalformedLine_RecordsError(t *testing.T) {
	raw := "Name      Version    Rev    Tracking       Publisher   Notes\n" +
		"short\n"
	result := ParseSnapOutput(raw)

	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "snap", result.Errs[0].Collector)
}

func TestParseSnapOutput_NoPublisherColumn(t *testing.T) {
	raw := "Name      Version    Rev\n" +
		"code      1.90.0     155\n"
	result := ParseSnapOutput(raw)

	require.Len(t, result.Items, 1)
	assert.Equal(t, "", result.Items[0].Vendor)
}

func TestParseSnapOutput_MissingNameColumn_ReturnsEmpty(t *testing.T) {
	raw := "Pkg       Version    Rev\n" +
		"code      1.90.0     155\n"
	result := ParseSnapOutput(raw)

	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}
