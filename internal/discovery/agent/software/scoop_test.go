package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseScoopOutput_ValidLines(t *testing.T) {
	raw := "Installed apps:\n\n" +
		"Name      Version  Source Updated             Info\n" +
		"----      -------  ------ -------             ----\n" +
		"7zip      24.08    main   2024-06-30 12:00:00\n" +
		"git       2.45.2   main   2024-06-30 12:00:00\n"

	result := ParseScoopOutput(raw)

	require.Len(t, result.Items, 2)
	assert.Equal(t, "7zip", result.Items[0].SoftwareName)
	assert.Equal(t, "24.08", result.Items[0].Version)
	assert.Equal(t, "scoop", result.Items[0].PackageManager)

	assert.Equal(t, "git", result.Items[1].SoftwareName)
	assert.Equal(t, "2.45.2", result.Items[1].Version)
	assert.False(t, result.HasErrors())
}

func TestParseScoopOutput_EmptyInput(t *testing.T) {
	result := ParseScoopOutput("")
	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseScoopOutput_NoHeader(t *testing.T) {
	raw := "No apps installed.\n"
	result := ParseScoopOutput(raw)

	assert.Empty(t, result.Items)
	assert.False(t, result.HasErrors())
}

func TestParseScoopOutput_MalformedLine_RecordsError(t *testing.T) {
	raw := "Name      Version  Source\n" +
		"----      -------  ------\n" +
		"short\n"
	result := ParseScoopOutput(raw)

	assert.Empty(t, result.Items)
	require.Len(t, result.Errs, 1)
	assert.Equal(t, "scoop", result.Errs[0].Collector)
}
