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

// Nix collects installed packages using nix-env on NixOS and Nix-based systems.
type Nix struct{}

// NewNix returns a new Nix collector.
func NewNix() *Nix { return &Nix{} }

// Name returns the stable identifier for this collector.
func (n *Nix) Name() string { return "nix" }

// Available reports whether nix-env is on the PATH.
func (n *Nix) Available() bool {
	_, err := exec.LookPath("nix-env")
	return err == nil
}

// Collect runs nix-env --query --installed and returns parsed results.
func (n *Nix) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "nix-env", "--query", "--installed")
	if err != nil {
		return nil, fmt.Errorf("nix-env --query: %w", err)
	}
	return ParseNixOutput(string(out)), nil
}

// ParseNixOutput parses the output of nix-env --query --installed.
// Each line is a "name-version" string where the version starts at the
// first hyphen followed by a digit.
func ParseNixOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		name, version := splitNameVersion(line)
		if name == "" || version == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "nix",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("cannot split package name and version"),
			})
			continue
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "nix",
			CPE23:          BuildCPE23("", name, version),
		})
	}

	return result
}

// Compile-time interface check.
var _ Collector = (*Nix)(nil)
