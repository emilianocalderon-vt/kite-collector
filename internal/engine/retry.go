package engine

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// maxRetryDelay caps the exponential backoff to prevent unbounded waits.
const maxRetryDelay = 30 * time.Second

// retry wraps a function with exponential backoff.
// Maps to the Python scaffold's @retry() decorator in resilience.py.
//
// The function fn is called up to maxAttempts times. On each failure the
// caller sleeps for baseDelay * 2^attempt, capped at 30 seconds. Context
// cancellation is checked between attempts so callers can abort early on
// shutdown signals.
func retry(ctx context.Context, maxAttempts int, baseDelay time.Duration, fn func() error) error {
	if maxAttempts <= 0 {
		return fmt.Errorf("retry: maxAttempts must be > 0, got %d", maxAttempts)
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		// Don't sleep after the final failed attempt.
		if attempt >= maxAttempts-1 {
			break
		}

		delay := baseDelay * time.Duration(1<<uint(attempt))
		if delay > maxRetryDelay {
			delay = maxRetryDelay
		}

		slog.Warn("retry: attempt failed, backing off",
			"attempt", attempt+1,
			"max_attempts", maxAttempts,
			"delay", delay.String(),
			"error", lastErr,
		)

		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return fmt.Errorf("retry: context cancelled after %d/%d attempts: %w", attempt+1, maxAttempts, ctx.Err())
		}
	}

	return fmt.Errorf("retry: all %d attempts exhausted: %w", maxAttempts, lastErr)
}
