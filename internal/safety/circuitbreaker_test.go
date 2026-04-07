package safety

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCB() *CircuitBreaker {
	return NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 3,
		CooldownDuration: 100 * time.Millisecond,
		SuccessThreshold: 1,
	})
}

func TestCircuitBreaker_StartsHealthy(t *testing.T) {
	cb := testCB()
	assert.Equal(t, CircuitHealthy, cb.State("docker"))
	assert.False(t, cb.ShouldSkip("docker"))
}

func TestCircuitBreaker_HealthyToDegradedOnFailure(t *testing.T) {
	cb := testCB()
	cb.RecordFailure("docker", "connection refused")
	assert.Equal(t, CircuitDegraded, cb.State("docker"))
	assert.False(t, cb.ShouldSkip("docker"))
}

func TestCircuitBreaker_DegradedToOpenOnThreshold(t *testing.T) {
	cb := testCB()
	cb.RecordFailure("docker", "err1")
	cb.RecordFailure("docker", "err2")
	cb.RecordFailure("docker", "err3")
	assert.Equal(t, CircuitOpen, cb.State("docker"))
	assert.True(t, cb.ShouldSkip("docker"))
}

func TestCircuitBreaker_OpenToHalfOpenAfterCooldown(t *testing.T) {
	cb := testCB()
	cb.RecordFailure("docker", "err1")
	cb.RecordFailure("docker", "err2")
	cb.RecordFailure("docker", "err3")
	assert.True(t, cb.ShouldSkip("docker"))

	time.Sleep(150 * time.Millisecond) // exceed cooldown

	assert.False(t, cb.ShouldSkip("docker"), "should allow probe after cooldown")
	assert.Equal(t, CircuitDegraded, cb.State("docker"))
}

func TestCircuitBreaker_HalfOpenToHealthyOnSuccess(t *testing.T) {
	cb := testCB()
	cb.RecordFailure("docker", "err1")
	cb.RecordFailure("docker", "err2")
	cb.RecordFailure("docker", "err3")

	time.Sleep(150 * time.Millisecond)
	cb.ShouldSkip("docker") // transitions to degraded

	cb.RecordSuccess("docker")
	assert.Equal(t, CircuitHealthy, cb.State("docker"))
}

func TestCircuitBreaker_HalfOpenToOpenOnFailure(t *testing.T) {
	cb := testCB()
	for i := 0; i < 3; i++ {
		cb.RecordFailure("docker", "err")
	}

	time.Sleep(150 * time.Millisecond)
	cb.ShouldSkip("docker") // half-open

	cb.RecordFailure("docker", "still broken")
	// After failure threshold (3) total consecutive failures now = 4 >= 3
	assert.Equal(t, CircuitOpen, cb.State("docker"))
}

func TestCircuitBreaker_SuccessResetsFailures(t *testing.T) {
	cb := testCB()
	cb.RecordFailure("docker", "err1")
	cb.RecordFailure("docker", "err2")
	cb.RecordSuccess("docker")
	// After success, failures reset. One more failure should not trip.
	cb.RecordFailure("docker", "err3")
	assert.NotEqual(t, CircuitOpen, cb.State("docker"))
}

func TestCircuitBreaker_MetricsIncremented(t *testing.T) {
	trips := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "test_trips",
	}, []string{"source"})
	health := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "test_health",
	}, []string{"source"})

	cb := testCB()
	cb.SetMetrics(trips, health)

	cb.RecordFailure("docker", "err1")
	cb.RecordFailure("docker", "err2")
	cb.RecordFailure("docker", "err3")

	tripVal := testutil.ToFloat64(trips.With(prometheus.Labels{"source": "docker"}))
	assert.Equal(t, float64(1), tripVal)

	healthVal := testutil.ToFloat64(health.With(prometheus.Labels{"source": "docker"}))
	assert.Equal(t, float64(0), healthVal) // open = 0
}

func TestCircuitBreaker_HealthGaugeValues(t *testing.T) {
	health := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "test_health_vals",
	}, []string{"source"})

	cb := testCB()
	cb.SetMetrics(nil, health)

	cb.RecordSuccess("s1")
	assert.Equal(t, float64(1.0), testutil.ToFloat64(health.With(prometheus.Labels{"source": "s1"})))

	cb.RecordFailure("s1", "err")
	assert.Equal(t, float64(0.5), testutil.ToFloat64(health.With(prometheus.Labels{"source": "s1"})))
}

func TestCircuitBreaker_MinimumThresholdEnforced(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: 1, // below minimum of 2
		CooldownDuration: 1 * time.Second,
		SuccessThreshold: 0, // below minimum of 1
	})
	// Should be clamped to 2 and 1 respectively
	s := cb.getOrCreate("test")
	assert.Equal(t, 2, s.failureThreshold)
	assert.Equal(t, 1, s.successThreshold)
}

func TestCircuitBreaker_AllSourceHealth(t *testing.T) {
	cb := testCB()
	cb.RecordSuccess("docker")
	cb.RecordFailure("proxmox", "timeout")

	health := cb.AllSourceHealth()
	assert.Len(t, health, 2)

	m := make(map[string]SourceHealth)
	for _, h := range health {
		m[h.SourceName] = h
	}

	assert.Equal(t, CircuitHealthy, m["docker"].State)
	assert.Equal(t, CircuitDegraded, m["proxmox"].State)
}

func TestCircuitBreaker_GetSourceHealth(t *testing.T) {
	cb := testCB()
	cb.RecordFailure("docker", "connection refused")

	h, err := cb.GetSourceHealth("docker")
	require.NoError(t, err)
	assert.Equal(t, "docker", h.SourceName)
	assert.Equal(t, CircuitDegraded, h.State)
	assert.Equal(t, 1, h.ConsecutiveFailures)
	assert.Equal(t, "connection refused", h.LastFailureReason)

	_, err = cb.GetSourceHealth("nonexistent")
	assert.Error(t, err)
}

func TestCircuitBreaker_TotalTripsIncrement(t *testing.T) {
	cb := testCB()

	// Trip once
	for i := 0; i < 3; i++ {
		cb.RecordFailure("docker", "err")
	}
	h, _ := cb.GetSourceHealth("docker")
	assert.Equal(t, 1, h.TotalTrips)

	// Recover and trip again
	time.Sleep(150 * time.Millisecond)
	cb.ShouldSkip("docker") // half-open
	cb.RecordSuccess("docker")

	for i := 0; i < 3; i++ {
		cb.RecordFailure("docker", "err again")
	}
	h, _ = cb.GetSourceHealth("docker")
	assert.Equal(t, 2, h.TotalTrips)
}

func TestCircuitBreaker_IndependentSources(t *testing.T) {
	cb := testCB()

	// Trip docker but not proxmox
	for i := 0; i < 3; i++ {
		cb.RecordFailure("docker", "err")
	}
	cb.RecordSuccess("proxmox")

	assert.True(t, cb.ShouldSkip("docker"))
	assert.False(t, cb.ShouldSkip("proxmox"))
}
