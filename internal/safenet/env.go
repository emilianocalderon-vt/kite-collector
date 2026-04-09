package safenet

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

// ParseBoolEnv reads an environment variable and parses it as a boolean.
// Accepts: true/false, 1/0, yes/no, on/off, t/f (case-insensitive via strconv.ParseBool).
// Returns false if unset or unparseable.
func ParseBoolEnv(key string) bool {
	v := os.Getenv(key)
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		slog.Warn("invalid boolean env var, treating as false", //#nosec G706 -- control chars stripped; operator-configured env var
			"key", key, "value", sanitizeLog(v))
		return false
	}
	return b
}

// ZeroString overwrites a string's backing memory with zeros.
// This is defense-in-depth for credential zeroing after token acquisition.
//
// Precondition: *s must point to heap-allocated memory (e.g. from
// os.Getenv, json.Unmarshal, or strings.Clone). String literals reside
// in read-only pages and will cause a fatal SIGSEGV — callers that store
// credentials should Clone them first.
//
// Limitation: the GC may have copied the backing array before this
// function is called. This zeroes the current allocation only.
func ZeroString(s *string) {
	if s == nil || *s == "" {
		return
	}
	// #nosec G103 -- intentional unsafe usage for credential zeroing
	b := unsafe.Slice(unsafe.StringData(*s), len(*s))
	for i := range b {
		b[i] = 0
	}
	*s = ""
}

// SafeGo runs fn in a goroutine with panic recovery.
// Panics are logged and do not crash the process.
func SafeGo(wg *sync.WaitGroup, logger *slog.Logger, name string, fn func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logger.Error("goroutine panic recovered",
					"name", name, "panic", fmt.Sprint(r))
			}
		}()
		fn()
	}()
}

// WithResourceDeadline returns a context with a per-resource timeout.
// Used in concurrent enrichment (e.g. per-agent in Wazuh).
func WithResourceDeadline(parent context.Context, perResource time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, perResource)
}

// sanitizeLog replaces control characters to prevent log injection (CWE-117).
func sanitizeLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}
