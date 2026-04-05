package software

import (
	"context"
	"fmt"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Collector is the interface that every platform-specific package manager
// backend must implement. Each collector knows how to enumerate installed
// packages from a single package manager.
type Collector interface {
	// Name returns a stable, lowercase identifier (e.g. "dpkg", "pacman").
	Name() string

	// Available reports whether this collector can run on the current system.
	// Implementations use exec.LookPath to probe for the binary.
	Available() bool

	// Collect runs the package manager query and returns parsed results.
	// Fatal errors (binary crashed, context cancelled) are returned as error.
	// Per-line parse failures go in Result.Errs.
	Collect(ctx context.Context) (*Result, error)
}

// CollectError represents a non-fatal parse failure on a single line of output.
type CollectError struct {
	Err       error  // underlying parse error
	Collector string // name of the collector that produced the error
	RawLine   string // the original text that could not be parsed
	Line      int    // 1-based line number in the raw output
}

// Error implements the error interface.
func (e *CollectError) Error() string {
	return fmt.Sprintf("%s: line %d: %v: %q", e.Collector, e.Line, e.Err, e.RawLine)
}

// Unwrap returns the underlying error for errors.Is / errors.As support.
func (e *CollectError) Unwrap() error {
	return e.Err
}

// Result holds the output of one or more collector runs. It supports partial
// success: Items may contain successfully parsed packages while Errs holds
// any per-line parse failures.
type Result struct {
	Items []model.InstalledSoftware
	Errs  []CollectError
}

// Merge appends all items and errors from other into r.
func (r *Result) Merge(other *Result) {
	r.Items = append(r.Items, other.Items...)
	r.Errs = append(r.Errs, other.Errs...)
}

// TotalErrors returns the number of parse errors collected.
func (r *Result) TotalErrors() int {
	return len(r.Errs)
}

// HasErrors reports whether any parse errors occurred.
func (r *Result) HasErrors() bool {
	return len(r.Errs) > 0
}
