package model

import (
	"time"

	"github.com/google/uuid"
)

// IncidentType classifies runtime incidents.
type IncidentType string

const (
	IncidentPanicRecovered       IncidentType = "panic_recovered"
	IncidentTimeoutExceeded      IncidentType = "timeout_exceeded"
	IncidentCircuitBreakerTrip   IncidentType = "circuit_breaker_tripped"
	IncidentResponseTruncated    IncidentType = "response_truncated"
	IncidentBodyLimitExceeded    IncidentType = "body_limit_exceeded"
)

// RuntimeIncident records a single runtime safety event such as a recovered
// panic, a circuit breaker trip, or a scan deadline exceeded.
type RuntimeIncident struct {
	CreatedAt    time.Time    `json:"created_at"`
	ScanRunID    *uuid.UUID   `json:"scan_run_id,omitempty"`
	IncidentType IncidentType `json:"incident_type"`
	Component    string       `json:"component"`
	ErrorMessage string       `json:"error_message"`
	StackTrace   string       `json:"stack_trace,omitempty"`
	Severity     string       `json:"severity"`
	ErrorCode    string       `json:"error_code,omitempty"`
	ID           uuid.UUID    `json:"id"`
	Recovered    bool         `json:"recovered"`
}
