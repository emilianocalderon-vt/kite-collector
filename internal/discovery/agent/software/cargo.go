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

// Cargo collects installed Rust crates using cargo install --list.
type Cargo struct{}

// NewCargo returns a new Cargo collector.
func NewCargo() *Cargo { return &Cargo{} }

// Name returns the stable identifier for this collector.
func (c *Cargo) Name() string { return "cargo" }

// Available reports whether cargo is on the PATH.
func (c *Cargo) Available() bool {
	_, err := exec.LookPath("cargo")
	return err == nil
}

// Collect runs cargo install --list and returns parsed results.
func (c *Cargo) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "cargo", "install", "--list")
	if err != nil {
		return nil, fmt.Errorf("cargo install --list: %w", err)
	}
	return ParseCargoOutput(string(out)), nil
}

// ParseCargoOutput parses the output of cargo install --list.
// Crate lines have the format "name vX.Y.Z:" and indented lines are
// sub-binaries which are skipped.
func ParseCargoOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Skip indented lines (sub-binaries).
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}

		// Crate lines end with ":"
		if !strings.HasSuffix(line, ":") {
			result.Errs = append(result.Errs, CollectError{
				Collector: "cargo",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'name vX.Y.Z:' format"),
			})
			continue
		}

		entry := strings.TrimSuffix(line, ":")
		parts := strings.Fields(entry)
		if len(parts) < 2 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "cargo",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'name vX.Y.Z:' format"),
			})
			continue
		}

		name := parts[0]
		version := strings.TrimPrefix(parts[1], "v")

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "cargo",
			CPE23:          BuildCPE23WithTargetSW("", name, version, "rust"),
		})
	}

	return result
}

// Compile-time interface check.
var _ Collector = (*Cargo)(nil)
