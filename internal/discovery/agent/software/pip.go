package software

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Pip collects globally installed Python packages using pip.
type Pip struct{}

// NewPip returns a new Pip collector.
func NewPip() *Pip { return &Pip{} }

// Name returns the stable identifier for this collector.
func (p *Pip) Name() string { return "pip" }

// Available reports whether pip3 or pip is on the PATH.
func (p *Pip) Available() bool {
	if _, err := exec.LookPath("pip3"); err == nil {
		return true
	}
	_, err := exec.LookPath("pip")
	return err == nil
}

// Collect runs pip list --format=json and returns parsed results.
func (p *Pip) Collect(ctx context.Context) (*Result, error) {
	binary := "pip"
	if _, err := exec.LookPath("pip3"); err == nil {
		binary = "pip3"
	}
	out, err := runWithLimits(ctx, binary, "list", "--format=json")
	if err != nil {
		return nil, fmt.Errorf("%s list: %w", binary, err)
	}
	return ParsePipJSON(string(out)), nil
}

// pipPackage represents a single entry in pip list --format=json output.
type pipPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ParsePipJSON parses the JSON output of pip list --format=json.
func ParsePipJSON(raw string) *Result {
	result := &Result{}
	if raw == "" {
		return result
	}

	var packages []pipPackage
	if err := json.Unmarshal([]byte(raw), &packages); err != nil {
		result.Errs = append(result.Errs, CollectError{
			Collector: "pip",
			Line:      1,
			RawLine:   truncateRaw(raw),
			Err:       fmt.Errorf("json decode: %w", err),
		})
		return result
	}

	for _, pkg := range packages {
		if pkg.Name == "" {
			continue
		}
		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   pkg.Name,
			Version:        pkg.Version,
			PackageManager: "pip",
			CPE23:          BuildCPE23WithTargetSW("", pkg.Name, pkg.Version, "python"),
		})
	}

	return result
}

// truncateRaw returns the first 200 bytes of s for error reporting.
func truncateRaw(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// Compile-time interface check.
var _ Collector = (*Pip)(nil)
