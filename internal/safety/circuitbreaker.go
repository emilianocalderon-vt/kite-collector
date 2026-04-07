package safety

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// CircuitState represents the health state of a discovery source.
type CircuitState string

const (
	CircuitHealthy  CircuitState = "healthy"
	CircuitDegraded CircuitState = "degraded"
	CircuitOpen     CircuitState = "open"
)

// CircuitBreakerConfig holds the configuration for a circuit breaker.
type CircuitBreakerConfig struct {
	FailureThreshold int
	CooldownDuration time.Duration
	SuccessThreshold int
}

// DefaultCircuitBreakerConfig returns sensible defaults.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold: 3,
		CooldownDuration: 5 * time.Minute,
		SuccessThreshold: 1,
	}
}

// sourceState tracks the circuit breaker state for a single source.
type sourceState struct {
	mu                   sync.Mutex
	state                CircuitState
	consecutiveFailures  int
	consecutiveSuccesses int
	failureThreshold     int
	cooldownDuration     time.Duration
	successThreshold     int
	lastFailureAt        time.Time
	lastSuccessAt        time.Time
	lastFailureReason    string
	totalTrips           int
}

// CircuitBreaker manages per-source circuit breaker state.
type CircuitBreaker struct {
	sources      sync.Map // map[string]*sourceState
	defaultCfg   CircuitBreakerConfig
	tripsCounter *prometheus.CounterVec
	healthGauge  *prometheus.GaugeVec
}

// NewCircuitBreaker creates a CircuitBreaker with the given default config.
func NewCircuitBreaker(cfg CircuitBreakerConfig) *CircuitBreaker {
	if cfg.FailureThreshold < 2 {
		cfg.FailureThreshold = 2
	}
	if cfg.CooldownDuration < 30*time.Second {
		cfg.CooldownDuration = 30 * time.Second
	}
	if cfg.SuccessThreshold < 1 {
		cfg.SuccessThreshold = 1
	}
	return &CircuitBreaker{
		defaultCfg: cfg,
	}
}

// SetMetrics sets the Prometheus metrics for circuit breaker trips and
// source health. Both are optional.
func (cb *CircuitBreaker) SetMetrics(trips *prometheus.CounterVec, health *prometheus.GaugeVec) {
	cb.tripsCounter = trips
	cb.healthGauge = health
}

// getOrCreate returns the state for a source, creating it if absent.
func (cb *CircuitBreaker) getOrCreate(sourceName string) *sourceState {
	if v, ok := cb.sources.Load(sourceName); ok {
		return v.(*sourceState)
	}
	s := &sourceState{
		state:            CircuitHealthy,
		failureThreshold: cb.defaultCfg.FailureThreshold,
		cooldownDuration: cb.defaultCfg.CooldownDuration,
		successThreshold: cb.defaultCfg.SuccessThreshold,
	}
	actual, _ := cb.sources.LoadOrStore(sourceName, s)
	return actual.(*sourceState)
}

// ShouldSkip returns true if the source's circuit is open and the
// cooldown has not yet elapsed. If the cooldown has elapsed, the
// circuit transitions to half-open (degraded) and returns false to
// allow a probe attempt.
func (cb *CircuitBreaker) ShouldSkip(sourceName string) bool {
	s := cb.getOrCreate(sourceName)
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != CircuitOpen {
		return false
	}

	if time.Since(s.lastFailureAt) >= s.cooldownDuration {
		s.state = CircuitDegraded
		slog.Info("circuit breaker half-open, allowing probe",
			"source", sourceName)
		cb.updateHealthGauge(sourceName, CircuitDegraded)
		return false
	}

	return true
}

// RecordSuccess records a successful invocation for the named source.
// It resets the failure counter and may transition the circuit from
// degraded to healthy.
func (cb *CircuitBreaker) RecordSuccess(sourceName string) {
	s := cb.getOrCreate(sourceName)
	s.mu.Lock()
	defer s.mu.Unlock()

	s.consecutiveSuccesses++
	s.consecutiveFailures = 0
	s.lastSuccessAt = time.Now()

	if s.state != CircuitHealthy && s.consecutiveSuccesses >= s.successThreshold {
		slog.Info("circuit breaker closed",
			"source", sourceName,
			"previous_state", string(s.state),
		)
		s.state = CircuitHealthy
	}

	cb.updateHealthGauge(sourceName, s.state)
}

// RecordFailure records a failed invocation for the named source.
// If the failure threshold is reached, the circuit opens.
func (cb *CircuitBreaker) RecordFailure(sourceName string, reason string) {
	s := cb.getOrCreate(sourceName)
	s.mu.Lock()
	defer s.mu.Unlock()

	s.consecutiveFailures++
	s.consecutiveSuccesses = 0
	s.lastFailureAt = time.Now()
	s.lastFailureReason = reason

	if s.state == CircuitHealthy && s.consecutiveFailures >= 1 {
		s.state = CircuitDegraded
	}

	if s.consecutiveFailures >= s.failureThreshold {
		if s.state != CircuitOpen {
			s.state = CircuitOpen
			s.totalTrips++
			slog.Warn("circuit breaker tripped",
				"source", sourceName,
				"consecutive_failures", s.consecutiveFailures,
				"threshold", s.failureThreshold,
				"cooldown", s.cooldownDuration,
				"total_trips", s.totalTrips,
			)
			if cb.tripsCounter != nil {
				cb.tripsCounter.With(prometheus.Labels{"source": sourceName}).Inc()
			}
		}
	}

	cb.updateHealthGauge(sourceName, s.state)
}

// State returns the current circuit state for a source.
func (cb *CircuitBreaker) State(sourceName string) CircuitState {
	s := cb.getOrCreate(sourceName)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// SourceHealth returns a snapshot of source health info suitable for
// API responses.
type SourceHealth struct {
	SourceName          string       `json:"source_name"`
	State               CircuitState `json:"state"`
	ConsecutiveFailures int          `json:"consecutive_failures"`
	ConsecutiveSuccesses int         `json:"consecutive_successes"`
	FailureThreshold    int          `json:"failure_threshold"`
	CooldownSeconds     int          `json:"cooldown_seconds"`
	LastSuccessAt       *time.Time   `json:"last_success_at,omitempty"`
	LastFailureAt       *time.Time   `json:"last_failure_at,omitempty"`
	LastFailureReason   string       `json:"last_failure_reason,omitempty"`
	TotalTrips          int          `json:"total_trips"`
}

// AllSourceHealth returns health info for all tracked sources.
func (cb *CircuitBreaker) AllSourceHealth() []SourceHealth {
	var results []SourceHealth
	cb.sources.Range(func(key, value any) bool {
		name := key.(string)
		s := value.(*sourceState)
		s.mu.Lock()
		h := SourceHealth{
			SourceName:           name,
			State:                s.state,
			ConsecutiveFailures:  s.consecutiveFailures,
			ConsecutiveSuccesses: s.consecutiveSuccesses,
			FailureThreshold:     s.failureThreshold,
			CooldownSeconds:      int(s.cooldownDuration.Seconds()),
			LastFailureReason:    s.lastFailureReason,
			TotalTrips:           s.totalTrips,
		}
		if !s.lastSuccessAt.IsZero() {
			t := s.lastSuccessAt
			h.LastSuccessAt = &t
		}
		if !s.lastFailureAt.IsZero() {
			t := s.lastFailureAt
			h.LastFailureAt = &t
		}
		s.mu.Unlock()
		results = append(results, h)
		return true
	})
	return results
}

// GetSourceHealth returns health info for a specific source.
func (cb *CircuitBreaker) GetSourceHealth(sourceName string) (*SourceHealth, error) {
	v, ok := cb.sources.Load(sourceName)
	if !ok {
		return nil, fmt.Errorf("source %q not found", sourceName)
	}
	s := v.(*sourceState)
	s.mu.Lock()
	defer s.mu.Unlock()

	h := &SourceHealth{
		SourceName:           sourceName,
		State:                s.state,
		ConsecutiveFailures:  s.consecutiveFailures,
		ConsecutiveSuccesses: s.consecutiveSuccesses,
		FailureThreshold:     s.failureThreshold,
		CooldownSeconds:      int(s.cooldownDuration.Seconds()),
		LastFailureReason:    s.lastFailureReason,
		TotalTrips:           s.totalTrips,
	}
	if !s.lastSuccessAt.IsZero() {
		t := s.lastSuccessAt
		h.LastSuccessAt = &t
	}
	if !s.lastFailureAt.IsZero() {
		t := s.lastFailureAt
		h.LastFailureAt = &t
	}
	return h, nil
}

func (cb *CircuitBreaker) updateHealthGauge(sourceName string, state CircuitState) {
	if cb.healthGauge == nil {
		return
	}
	var val float64
	switch state {
	case CircuitHealthy:
		val = 1.0
	case CircuitDegraded:
		val = 0.5
	case CircuitOpen:
		val = 0.0
	}
	cb.healthGauge.With(prometheus.Labels{"source": sourceName}).Set(val)
}
