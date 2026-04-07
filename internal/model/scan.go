package model

import (
	"time"

	"github.com/google/uuid"
)

// ScanRun tracks the state and statistics of a single discovery scan execution.
type ScanRun struct {
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	StartedAt        time.Time  `json:"started_at"`
	ScopeConfig      string     `json:"scope_config"`      // JSON
	DiscoverySources string     `json:"discovery_sources"` // []string stored as JSON string
	Status           ScanStatus `json:"status"`
	ID               uuid.UUID  `json:"id"`
	CoveragePercent  float64    `json:"coverage_percent"`
	TotalAssets      int        `json:"total_assets"`
	NewAssets        int        `json:"new_assets"`
	UpdatedAssets    int        `json:"updated_assets"`
	StaleAssets      int        `json:"stale_assets"`
	ErrorCount       int        `json:"error_count"`
}

// ScanResult is a summary returned after a scan completes.
type ScanResult struct {
	Status             string  `json:"status"`
	TotalAssets        int     `json:"total_assets"`
	NewAssets          int     `json:"new_assets"`
	UpdatedAssets      int     `json:"updated_assets"`
	StaleAssets        int     `json:"stale_assets"`
	EventsEmitted      int     `json:"events_emitted"`
	SoftwareCount      int     `json:"software_count"`
	SoftwareErrors     int     `json:"software_errors"`
	FindingsCount      int     `json:"findings_count"`
	PostureCount       int     `json:"posture_count"`
	ErrorCount         int     `json:"error_count"`
	PanicsRecovered    int     `json:"panics_recovered"`
	SourcesCircuitOpen int     `json:"sources_circuit_open"`
	SourcesFailed      int     `json:"sources_failed"`
	CoveragePercent    float64 `json:"coverage_percent"`
}
