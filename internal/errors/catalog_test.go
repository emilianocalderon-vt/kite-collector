package errors

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookup_Known(t *testing.T) {
	e := Lookup("KITE-E001")
	require.NotNil(t, e)
	assert.Equal(t, "KITE-E001", e.Code)
	assert.Equal(t, "Docker not accessible", e.Message)
	assert.NotEmpty(t, e.Cause)
}

func TestLookup_CaseInsensitive(t *testing.T) {
	e := Lookup("kite-e001")
	require.NotNil(t, e)
	assert.Equal(t, "KITE-E001", e.Code)
}

func TestLookup_Unknown(t *testing.T) {
	e := Lookup("KITE-E999")
	assert.Nil(t, e)
}

func TestRemediationFor_OSSpecific(t *testing.T) {
	e := Lookup("KITE-E001")
	require.NotNil(t, e)

	r := e.RemediationFor("linux")
	assert.Contains(t, r, "systemctl")

	r = e.RemediationFor("darwin")
	assert.Contains(t, r, "Docker Desktop")

	r = e.RemediationFor("windows")
	assert.Contains(t, r, "Docker Desktop")
}

func TestRemediationFor_DefaultFallback(t *testing.T) {
	e := Lookup("KITE-E004")
	require.NotNil(t, e)

	// KITE-E004 only has "default"; any GOOS should fall back.
	r := e.RemediationFor("freebsd")
	assert.Contains(t, r, "timeout")
}

func TestFormat_ContainsAllFields(t *testing.T) {
	e := Lookup("KITE-E001")
	require.NotNil(t, e)

	formatted := e.Format()
	assert.Contains(t, formatted, "KITE-E001")
	assert.Contains(t, formatted, "Docker not accessible")
	assert.Contains(t, formatted, runtime.GOOS)
}

func TestCodes_ReturnsAll(t *testing.T) {
	codes := Codes()
	assert.Len(t, codes, len(Catalog))
	assert.Equal(t, "KITE-E001", codes[0])
	assert.Equal(t, "KITE-E015", codes[len(codes)-1])
}

func TestCodes_Sorted(t *testing.T) {
	codes := Codes()
	for i := 1; i < len(codes); i++ {
		assert.True(t, codes[i-1] < codes[i], "codes should be sorted: %s < %s", codes[i-1], codes[i])
	}
}

func TestCatalogCompleteness(t *testing.T) {
	// Every entry must have non-empty required fields.
	for code, e := range Catalog {
		assert.Equal(t, code, e.Code, "map key must match Code field")
		assert.NotEmpty(t, e.Message, "Message empty for %s", code)
		assert.NotEmpty(t, e.Cause, "Cause empty for %s", code)
		assert.NotEmpty(t, e.Remediation, "Remediation empty for %s", code)

		// Must have at least a "default" or an OS-specific entry.
		hasEntry := false
		for _, r := range e.Remediation {
			if r != "" {
				hasEntry = true
				break
			}
		}
		assert.True(t, hasEntry, "Remediation has no non-empty entries for %s", code)
	}
}
