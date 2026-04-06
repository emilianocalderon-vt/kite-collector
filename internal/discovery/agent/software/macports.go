// macports.go
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

type MacPorts struct{}

func NewMacPorts() *MacPorts { return &MacPorts{} }

func (m *MacPorts) Name() string { return "macports" }

func (m *MacPorts) Available() bool {
	_, err := exec.LookPath("port")
	return err == nil
}

func (m *MacPorts) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "port", "installed")
	if err != nil {
		return nil, fmt.Errorf("port installed: %w", err)
	}
	return ParseMacPortsOutput(string(out)), nil
}

// ParseMacPortsOutput parses the output of port installed.
// Lines are "  name @version_revision+variants (active)".
func ParseMacPortsOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Skip non-indented lines (header).
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			continue
		}

		trimmed := strings.TrimSpace(line)
		atIdx := strings.Index(trimmed, " @")
		if atIdx <= 0 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "macports",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'name @version' format"),
			})
			continue
		}

		name := trimmed[:atIdx]
		rest := trimmed[atIdx+2:] // skip " @"

		// Strip trailing "(active)" or "(inactive)" and variants.
		if sp := strings.IndexByte(rest, ' '); sp > 0 {
			rest = rest[:sp]
		}

		// Strip +variants suffix.
		if plus := strings.IndexByte(rest, '+'); plus > 0 {
			rest = rest[:plus]
		}

		// Strip _revision suffix.
		if us := strings.IndexByte(rest, '_'); us > 0 {
			rest = rest[:us]
		}

		version := rest

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "macports",
			Vendor:         "macports",
			CPE23:          BuildCPE23("macports", name, version),
		})
	}

	return result
}

var _ Collector = (*MacPorts)(nil)
