package correlation

// Engine performs local CPE-to-host correlation using API response data.
// The SaaS returns CPEMatch records keyed by CPE; the engine maps them
// onto hosts using the agent's private host→software inventory.
type Engine struct{}

// NewEngine creates a correlation engine.
func NewEngine() *Engine { return &Engine{} }

// Correlate takes API response matches and local software inventory
// (hostname → []CPE), returning per-host vulnerability mappings.
// Hosts with zero matching CPEs are excluded from the result.
func (e *Engine) Correlate(response *Response, hostSoftware map[string][]string) []LocalCorrelation {
	matchByCPE := make(map[string]CPEMatch, len(response.Matches))
	for _, m := range response.Matches {
		matchByCPE[m.CPE] = m
	}

	var results []LocalCorrelation
	for hostname, cpes := range hostSoftware {
		lc := LocalCorrelation{Hostname: hostname}
		seen := make(map[string]bool)
		var maxScore float64

		for _, cpe := range cpes {
			m, ok := matchByCPE[cpe]
			if !ok {
				continue
			}
			lc.Matches = append(lc.Matches, m)
			for _, cveID := range m.CVEIDs {
				if !seen[cveID] {
					seen[cveID] = true
					lc.TotalCVEs++
				}
			}
			if m.MaxCVSSBase > maxScore {
				maxScore = m.MaxCVSSBase
			}
		}

		if len(lc.Matches) == 0 {
			continue
		}
		lc.MaxSeverity = SeverityFromCVSS(maxScore)
		results = append(results, lc)
	}
	return results
}

// Aggregate computes fleet-level statistics from per-host correlations.
// totalAssets is the full asset count (including those with no CVEs).
// Only these aggregate numbers are safe to send to the SaaS.
func (e *Engine) Aggregate(correlations []LocalCorrelation, totalAssets int) AggregateStats {
	stats := AggregateStats{TotalAssets: totalAssets}
	globalSeen := make(map[string]bool)
	var maxScore float64

	for _, lc := range correlations {
		if len(lc.Matches) > 0 {
			stats.AffectedAssets++
		}
		for _, m := range lc.Matches {
			if m.KEVFlagged {
				stats.KEVCount++
			}
			for _, cveID := range m.CVEIDs {
				if !globalSeen[cveID] {
					globalSeen[cveID] = true
					sev := SeverityFromCVSS(m.MaxCVSSBase)
					switch sev {
					case "critical":
						stats.CriticalCVEs++
					case "high":
						stats.HighCVEs++
					case "medium":
						stats.MediumCVEs++
					case "low":
						stats.LowCVEs++
					}
				}
			}
			if m.MaxCVSSBase > maxScore {
				maxScore = m.MaxCVSSBase
			}
		}
	}

	stats.TotalUniqueCVEs = len(globalSeen)
	stats.MaxSeverity = SeverityFromCVSS(maxScore)
	return stats
}

// DeduplicateCPEs returns unique, non-empty CPEs from all hosts' inventories.
// This is the set sent to the SaaS — deduplicated to minimise information
// leakage (the SaaS cannot determine per-host software distribution).
func DeduplicateCPEs(hostSoftware map[string][]string) []string {
	seen := make(map[string]bool)
	var unique []string
	for _, cpes := range hostSoftware {
		for _, cpe := range cpes {
			if cpe != "" && !seen[cpe] {
				seen[cpe] = true
				unique = append(unique, cpe)
			}
		}
	}
	return unique
}
