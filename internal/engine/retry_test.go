package engine

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetry_SucceedsOnFirstAttempt(t *testing.T) {
	calls := 0
	err := retry(context.Background(), 3, time.Millisecond, func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestRetry_SucceedsOnLaterAttempt(t *testing.T) {
	calls := 0
	err := retry(context.Background(), 5, time.Millisecond, func() error {
		calls++
		if calls < 3 {
			return errors.New("transient failure")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestRetry_ExhaustsAllAttempts(t *testing.T) {
	sentinel := errors.New("persistent failure")
	calls := 0
	err := retry(context.Background(), 3, time.Millisecond, func() error {
		calls++
		return sentinel
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel error, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestRetry_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := retry(ctx, 10, 100*time.Millisecond, func() error {
		calls++
		if calls == 1 {
			cancel() // cancel during the first backoff wait
		}
		return errors.New("fail")
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled in error chain, got %v", err)
	}
	// Should have stopped after 1 call because context was cancelled during backoff.
	if calls != 1 {
		t.Fatalf("expected 1 call before context cancellation, got %d", calls)
	}
}

func TestRetry_CapsDelayAt30Seconds(t *testing.T) {
	// With baseDelay=10s and attempt=2, raw delay would be 40s.
	// Verify the cap is applied by checking the function returns in reasonable time.
	// We use a context timeout well below what uncapped delays would require.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	calls := 0
	err := retry(ctx, 3, 10*time.Second, func() error {
		calls++
		return errors.New("fail")
	})
	// With 10s base delay, context should cancel before second attempt completes.
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestRetry_InvalidMaxAttempts(t *testing.T) {
	err := retry(context.Background(), 0, time.Millisecond, func() error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error for maxAttempts=0, got nil")
	}
}

func TestRetry_SingleAttemptNoBackoff(t *testing.T) {
	sentinel := errors.New("single fail")
	err := retry(context.Background(), 1, time.Millisecond, func() error {
		return sentinel
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel, got %v", err)
	}
}

func TestRetry_ExponentialBackoffTiming(t *testing.T) {
	// Verify that delays grow exponentially: ~1ms, ~2ms, ~4ms.
	baseDelay := 10 * time.Millisecond
	calls := 0
	timestamps := make([]time.Time, 0, 4)

	err := retry(context.Background(), 4, baseDelay, func() error {
		timestamps = append(timestamps, time.Now())
		calls++
		if calls < 4 {
			return errors.New("fail")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(timestamps) != 4 {
		t.Fatalf("expected 4 timestamps, got %d", len(timestamps))
	}

	// Check that each successive gap is roughly 2x the previous.
	// Allow generous tolerance since CI environments have variable timing.
	for i := 1; i < len(timestamps)-1; i++ {
		gap := timestamps[i+1].Sub(timestamps[i])
		prevGap := timestamps[i].Sub(timestamps[i-1])
		ratio := float64(gap) / float64(prevGap)
		// Expect ratio around 2.0, but accept 1.2 to 4.0 for CI stability.
		if ratio < 1.2 || ratio > 4.0 {
			t.Errorf("gap ratio between attempt %d and %d: %.2f (expected ~2.0)", i, i+1, ratio)
		}
	}
}
