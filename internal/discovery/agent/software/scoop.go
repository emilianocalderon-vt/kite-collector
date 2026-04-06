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

// Scoop collects installed packages using Scoop on Windows.
type Scoop struct{}

// NewScoop returns a new Scoop collector.
func NewScoop() *Scoop { return &Scoop{} }

// Name returns the stable identifier for this collector.
func (s *Scoop) Name() string { return "scoop" }

// Available reports whether scoop is on the PATH.
func (s *Scoop) Available() bool {
	_, err := exec.LookPath("scoop")
	return err == nil
}

// Collect runs scoop list and returns parsed results.
func (s *Scoop) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "scoop", "list")
	if err != nil {
		return nil, fmt.Errorf("scoop list: %w", err)
	}
	return ParseScoopOutput(string(out)), nil
}

// ParseScoopOutput parses the table output of scoop list.
// It looks for the header containing "Name" and "Version", skips the
// separator line, then parses whitespace-separated data rows.
func ParseScoopOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))

	// Find the header line containing "Name" and "Version".
	nameIdx, versionIdx := -1, -1
	headerFound := false
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		colIdx := indexColumns(fields, "Name", "Version")
		if colIdx["Name"] >= 0 && colIdx["Version"] >= 0 {
			nameIdx = colIdx["Name"]
			versionIdx = colIdx["Version"]
			headerFound = true
			break
		}
	}
	if !headerFound {
		return result
	}

	// Skip the separator line (dashes).
	if scanner.Scan() {
		_ = scanner.Text()
	}

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		minLen := versionIdx
		if nameIdx > minLen {
			minLen = nameIdx
		}
		if len(fields) <= minLen {
			result.Errs = append(result.Errs, CollectError{
				Collector: "scoop",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("not enough columns"),
			})
			continue
		}

		name := fields[nameIdx]
		version := fields[versionIdx]

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "scoop",
			CPE23:          BuildCPE23("", name, version),
		})
	}

	return result
}

// Compile-time interface check.
var _ Collector = (*Scoop)(nil)
