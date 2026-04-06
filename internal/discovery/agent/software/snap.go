package software

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Snap collects installed packages using Snap on Linux.
type Snap struct{}

// NewSnap returns a new Snap collector.
func NewSnap() *Snap { return &Snap{} }

// Name returns the stable identifier for this collector.
func (s *Snap) Name() string { return "snap" }

// Available reports whether snap is on the PATH.
func (s *Snap) Available() bool {
	_, err := exec.LookPath("snap")
	return err == nil
}

// Collect runs snap list and returns parsed results.
func (s *Snap) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "snap", "list")
	if err != nil {
		return nil, fmt.Errorf("snap list: %w", err)
	}
	return ParseSnapOutput(string(out)), nil
}

// ParseSnapOutput parses the output of snap list.
// The first line is a header; fields are whitespace-separated.
// Columns: Name, Version, Rev, Tracking, Publisher, Notes.
func ParseSnapOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	// Read header to find column indices.
	if !scanner.Scan() {
		return result
	}
	header := scanner.Text()
	colIdx := indexColumns(strings.Fields(header), "Name", "Version", "Publisher")
	nameIdx := colIdx["Name"]
	versionIdx := colIdx["Version"]
	publisherIdx := colIdx["Publisher"]

	if versionIdx < 0 {
		return result
	}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) <= versionIdx {
			result.Errs = append(result.Errs, CollectError{
				Collector: "snap",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("not enough columns"),
			})
			continue
		}

		name := fields[nameIdx]
		version := fields[versionIdx]

		publisher := ""
		if publisherIdx >= 0 && publisherIdx < len(fields) {
			publisher = stripVerified(fields[publisherIdx])
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Vendor:         publisher,
			Version:        version,
			PackageManager: "snap",
			CPE23:          BuildCPE23(publisher, name, version),
		})
	}

	return result
}

// indexColumns returns a map of column name to its 0-based index in the
// fields slice. Missing columns get index -1.
func indexColumns(fields []string, names ...string) map[string]int {
	m := make(map[string]int, len(names))
	for _, n := range names {
		m[n] = -1
	}
	for i, f := range fields {
		if _, ok := m[f]; ok {
			m[f] = i
		}
	}
	return m
}

// stripVerified removes Unicode verification marks from publisher names.
func stripVerified(s string) string {
	s = strings.TrimRight(s, "\u2713\u2714") // ✓ ✔
	return strings.TrimSpace(s)
}

// Compile-time interface check.
var _ Collector = (*Snap)(nil)
