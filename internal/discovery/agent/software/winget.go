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

// Winget collects installed packages using winget on Windows.
type Winget struct{}

// NewWinget returns a new Winget collector.
func NewWinget() *Winget { return &Winget{} }

// Name returns the stable identifier for this collector.
func (w *Winget) Name() string { return "winget" }

// Available reports whether winget is on the PATH.
func (w *Winget) Available() bool {
	_, err := exec.LookPath("winget")
	return err == nil
}

// Collect runs winget list and returns parsed results.
func (w *Winget) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "winget", "list", "--source", "winget", "--disable-interactivity")
	if err != nil {
		return nil, fmt.Errorf("winget list: %w", err)
	}
	return ParseWingetOutput(string(out)), nil
}

// ParseWingetOutput parses the fixed-width table output of winget list.
// It locates the header row with "Name", "Id", "Version" columns and
// uses their byte positions to extract fields from each data row.
func ParseWingetOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))

	// Phase 1: locate the header line.
	var idStart, versionStart, versionEnd int
	headerFound := false
	for scanner.Scan() {
		line := scanner.Text()
		iID := strings.Index(line, "Id")
		iVer := strings.Index(line, "Version")
		if iID >= 0 && iVer >= 0 && iVer > iID {
			idStart = iID
			versionStart = iVer
			// Look for the column after Version (commonly "Available" or "Source").
			versionEnd = len(line)
			if idx := strings.Index(line, "Available"); idx > versionStart {
				versionEnd = idx
			} else if idx := strings.Index(line, "Source"); idx > versionStart {
				versionEnd = idx
			}
			headerFound = true
			break
		}
	}
	if !headerFound {
		return result
	}

	// Phase 2: skip the separator line (dashes).
	if scanner.Scan() {
		sep := scanner.Text()
		if !strings.Contains(sep, "---") {
			// Not a separator; treat as first data line? Be conservative: skip.
			_ = sep
		}
	}

	// Phase 3: parse data rows.
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		if len(line) < versionStart {
			result.Errs = append(result.Errs, CollectError{
				Collector: "winget",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("line too short for column layout"),
			})
			continue
		}

		displayName := strings.TrimSpace(safeSubstring(line, 0, idStart))
		id := strings.TrimSpace(safeSubstring(line, idStart, versionStart))
		version := strings.TrimSpace(safeSubstring(line, versionStart, versionEnd))

		if id == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "winget",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("missing package Id"),
			})
			continue
		}

		vendor := ""
		if dot := strings.Index(id, "."); dot > 0 {
			vendor = id[:dot]
		}

		if displayName == "" {
			displayName = id
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   displayName,
			Vendor:         vendor,
			Version:        version,
			PackageManager: "winget",
			CPE23:          BuildCPE23(vendor, displayName, version),
		})
	}

	return result
}

// safeSubstring returns line[start:end] clamped to the line length.
func safeSubstring(line string, start, end int) string {
	if start >= len(line) {
		return ""
	}
	if end > len(line) {
		end = len(line)
	}
	return line[start:end]
}

// Compile-time interface check.
var _ Collector = (*Winget)(nil)
