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

// Brew collects installed packages using Homebrew on macOS and Linux.
type Brew struct{}

// NewBrew returns a new Brew collector.
func NewBrew() *Brew { return &Brew{} }

// Name returns the stable identifier for this collector.
func (b *Brew) Name() string { return "brew" }

// Available reports whether brew is on the PATH.
func (b *Brew) Available() bool {
	_, err := exec.LookPath("brew")
	return err == nil
}

// Collect runs brew list --versions and returns parsed results.
func (b *Brew) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "brew", "list", "--versions")
	if err != nil {
		return nil, fmt.Errorf("brew list --versions: %w", err)
	}
	return ParseBrewOutput(string(out)), nil
}

// ParseBrewOutput parses the raw output of brew list --versions.
// Each line is expected as "<package> <version> [version2 ...]".
// Only the first (most recent) version is captured.
func ParseBrewOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "brew",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'package version [version ...]' format"),
			})
			continue
		}

		name := parts[0]
		version := parts[1]

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Vendor:         "homebrew",
			Version:        version,
			PackageManager: "brew",
			CPE23:          BuildCPE23("homebrew", name, version),
		})
	}

	return result
}

// Compile-time interface check.
var _ Collector = (*Brew)(nil)
