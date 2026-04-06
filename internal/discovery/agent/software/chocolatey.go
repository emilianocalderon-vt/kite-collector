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

// Chocolatey collects installed packages using Chocolatey on Windows.
type Chocolatey struct{}

// NewChocolatey returns a new Chocolatey collector.
func NewChocolatey() *Chocolatey { return &Chocolatey{} }

// Name returns the stable identifier for this collector.
func (c *Chocolatey) Name() string { return "chocolatey" }

// Available reports whether choco is on the PATH.
func (c *Chocolatey) Available() bool {
	_, err := exec.LookPath("choco")
	return err == nil
}

// Collect runs choco list --local-only and returns parsed results.
func (c *Chocolatey) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "choco", "list", "--local-only")
	if err != nil {
		return nil, fmt.Errorf("choco list: %w", err)
	}
	return ParseChocolateyOutput(string(out)), nil
}

// ParseChocolateyOutput parses the raw output of choco list --local-only.
// Skips the "Chocolatey v..." header line and the "N packages installed." footer.
func ParseChocolateyOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "Chocolatey v") {
			continue
		}
		if strings.HasSuffix(line, " packages installed.") {
			continue
		}

		idx := strings.LastIndex(line, " ")
		if idx <= 0 || idx >= len(line)-1 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "chocolatey",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'package version' format"),
			})
			continue
		}

		name := line[:idx]
		version := line[idx+1:]

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "chocolatey",
			CPE23:          BuildCPE23("", name, version),
		})
	}

	return result
}

// Compile-time interface check.
var _ Collector = (*Chocolatey)(nil)
