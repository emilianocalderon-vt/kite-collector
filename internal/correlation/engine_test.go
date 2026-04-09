package correlation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeverityFromCVSS(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{10.0, "critical"},
		{9.0, "critical"},
		{8.5, "high"},
		{7.0, "high"},
		{6.9, "medium"},
		{4.0, "medium"},
		{3.9, "low"},
		{0.1, "low"},
		{0.0, "none"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, SeverityFromCVSS(tt.score), "score=%.1f", tt.score)
	}
}

func TestDeduplicateCPEs(t *testing.T) {
	hostSoftware := map[string][]string{
		"web-01": {"cpe:2.3:a:apache:httpd:2.4.58:*:*:*:*:*:*:*", "cpe:2.3:a:openssl:openssl:3.2.0:*:*:*:*:*:*:*"},
		"web-02": {"cpe:2.3:a:apache:httpd:2.4.58:*:*:*:*:*:*:*", "cpe:2.3:a:nginx:nginx:1.25.4:*:*:*:*:*:*:*"},
		"db-01":  {"", "cpe:2.3:a:openssl:openssl:3.2.0:*:*:*:*:*:*:*"},
	}

	cpes := DeduplicateCPEs(hostSoftware)
	assert.Len(t, cpes, 3)

	seen := make(map[string]bool)
	for _, cpe := range cpes {
		assert.NotEmpty(t, cpe, "empty CPEs should be excluded")
		assert.False(t, seen[cpe], "duplicate CPE: %s", cpe)
		seen[cpe] = true
	}
}

func TestEngineCorrelate(t *testing.T) {
	engine := NewEngine()

	response := &Response{
		Matches: []CPEMatch{
			{
				CPE:         "cpe:2.3:a:apache:httpd:2.4.58:*:*:*:*:*:*:*",
				CVEIDs:      []string{"CVE-2024-0001", "CVE-2024-0002"},
				MaxCVSSBase: 9.8,
				MaxSeverity: "critical",
				KEVFlagged:  true,
				MaxEPSS:     0.89,
				CVECount:    2,
			},
			{
				CPE:         "cpe:2.3:a:openssl:openssl:3.2.0:*:*:*:*:*:*:*",
				CVEIDs:      []string{"CVE-2024-0003"},
				MaxCVSSBase: 7.5,
				MaxSeverity: "high",
				KEVFlagged:  false,
				MaxEPSS:     0.42,
				CVECount:    1,
			},
		},
		TotalCVEs:   3,
		MaxSeverity: "critical",
	}

	hostSoftware := map[string][]string{
		"web-01": {
			"cpe:2.3:a:apache:httpd:2.4.58:*:*:*:*:*:*:*",
			"cpe:2.3:a:openssl:openssl:3.2.0:*:*:*:*:*:*:*",
		},
		"web-02": {
			"cpe:2.3:a:apache:httpd:2.4.58:*:*:*:*:*:*:*",
		},
		"db-01": {
			"cpe:2.3:a:postgresql:postgresql:16.1:*:*:*:*:*:*:*",
		},
	}

	results := engine.Correlate(response, hostSoftware)

	// db-01 has no matching CPEs, so it should be excluded
	require.Len(t, results, 2)

	byHost := make(map[string]LocalCorrelation)
	for _, r := range results {
		byHost[r.Hostname] = r
	}

	web01 := byHost["web-01"]
	assert.Len(t, web01.Matches, 2)
	assert.Equal(t, 3, web01.TotalCVEs)
	assert.Equal(t, "critical", web01.MaxSeverity)

	web02 := byHost["web-02"]
	assert.Len(t, web02.Matches, 1)
	assert.Equal(t, 2, web02.TotalCVEs)
	assert.Equal(t, "critical", web02.MaxSeverity)
}

func TestEngineAggregate(t *testing.T) {
	engine := NewEngine()

	correlations := []LocalCorrelation{
		{
			Hostname: "web-01",
			Matches: []CPEMatch{
				{CVEIDs: []string{"CVE-2024-0001"}, MaxCVSSBase: 9.8, KEVFlagged: true},
				{CVEIDs: []string{"CVE-2024-0002"}, MaxCVSSBase: 5.5, KEVFlagged: false},
			},
			TotalCVEs: 2,
		},
		{
			Hostname: "web-02",
			Matches: []CPEMatch{
				{CVEIDs: []string{"CVE-2024-0001"}, MaxCVSSBase: 9.8, KEVFlagged: true},
			},
			TotalCVEs: 1,
		},
	}

	stats := engine.Aggregate(correlations, 5)
	assert.Equal(t, 5, stats.TotalAssets)
	assert.Equal(t, 2, stats.AffectedAssets)
	assert.Equal(t, 2, stats.TotalUniqueCVEs)
	assert.Equal(t, 1, stats.CriticalCVEs)
	assert.Equal(t, 1, stats.MediumCVEs)
	assert.Equal(t, "critical", stats.MaxSeverity)
	assert.Equal(t, 2, stats.KEVCount) // counted per host-match
}
