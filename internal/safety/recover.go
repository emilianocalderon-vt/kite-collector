// Package safety provides panic recovery wrappers and runtime safety
// utilities for kite-collector goroutines, HTTP handlers, and gRPC
// interceptors.
package safety

import (
	"fmt"
	"log/slog"
	"runtime/debug"

	"github.com/prometheus/client_golang/prometheus"
)

// Recover catches a panic in a deferred call, logs it with a stack trace,
// and increments the supplied Prometheus counter. If retErr is non-nil, it
// is set to an error describing the panic.
//
// Usage:
//
//	defer safety.Recover("discovery.docker", counter, &err)
func Recover(component string, counter *prometheus.CounterVec, retErr *error) {
	r := recover()
	if r == nil {
		return
	}
	stack := string(debug.Stack())
	slog.Error("panic recovered",
		"component", component,
		"error", fmt.Sprint(r),
		"stack_trace", stack,
	)
	if counter != nil {
		counter.With(prometheus.Labels{"component": component}).Inc()
	}
	if retErr != nil {
		*retErr = fmt.Errorf("panic in %s: %v", component, r)
	}
}

// LogPanic logs a recovered panic and increments the counter. Use this
// helper when the caller handles recover() itself (e.g., when additional
// cleanup such as a channel send is needed in the same defer).
func LogPanic(component string, panicVal any, stack string, counter *prometheus.CounterVec) {
	slog.Error("panic recovered",
		"component", component,
		"error", fmt.Sprint(panicVal),
		"stack_trace", stack,
	)
	if counter != nil {
		counter.With(prometheus.Labels{"component": component}).Inc()
	}
}
