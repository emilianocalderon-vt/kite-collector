package safenet

import (
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBoolEnv(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"true", "true", true},
		{"TRUE", "TRUE", true},
		{"True", "True", true},
		{"1", "1", true},
		{"t", "t", true},
		{"false", "false", false},
		{"FALSE", "FALSE", false},
		{"0", "0", false},
		{"f", "f", false},
		{"empty", "", false},
		{"invalid string", "maybe", false},
		{"yes is invalid for ParseBool", "yes", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TEST_BOOL", tt.value)
			assert.Equal(t, tt.want, ParseBoolEnv("TEST_BOOL"))
		})
	}

	t.Run("unset env returns false", func(t *testing.T) {
		assert.False(t, ParseBoolEnv("DEFINITELY_NOT_SET_ENV_VAR_XYZ"))
	})
}

func TestZeroString(t *testing.T) {
	t.Run("zeros a heap-allocated string", func(t *testing.T) {
		// Build a string that is heap-allocated (not a literal).
		parts := []string{"secret", "password"}
		s := parts[0] + parts[1]
		ZeroString(&s)
		assert.Equal(t, "", s)
	})

	t.Run("no panic on nil pointer", func(t *testing.T) {
		assert.NotPanics(t, func() { ZeroString(nil) })
	})

	t.Run("no panic on empty string", func(t *testing.T) {
		s := ""
		assert.NotPanics(t, func() { ZeroString(&s) })
		assert.Equal(t, "", s)
	})
}

func TestSafeGo(t *testing.T) {
	t.Run("normal function executes", func(t *testing.T) {
		var wg sync.WaitGroup
		executed := false
		SafeGo(&wg, slog.Default(), "test-normal", func() {
			executed = true
		})
		wg.Wait()
		assert.True(t, executed)
	})

	t.Run("panic is recovered", func(t *testing.T) {
		var wg sync.WaitGroup
		SafeGo(&wg, slog.Default(), "test-panic", func() {
			panic("test panic")
		})
		wg.Wait()
		// If we reach here, the panic was recovered and did not crash.
	})

	t.Run("wg is done even on panic", func(t *testing.T) {
		var wg sync.WaitGroup
		SafeGo(&wg, slog.Default(), "test-wg-panic", func() {
			panic("boom")
		})
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
			// success
		case <-time.After(2 * time.Second):
			t.Fatal("WaitGroup not released after panic")
		}
	})
}

func TestWithResourceDeadline(t *testing.T) {
	t.Run("returns context with deadline", func(t *testing.T) {
		ctx, cancel := WithResourceDeadline(t.Context(), 5*time.Second)
		defer cancel()

		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		assert.WithinDuration(t, time.Now().Add(5*time.Second), deadline, time.Second)
	})
}
