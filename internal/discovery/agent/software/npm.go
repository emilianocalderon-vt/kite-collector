package software

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Npm collects globally installed Node.js packages using npm.
type Npm struct{}

// NewNpm returns a new Npm collector.
func NewNpm() *Npm { return &Npm{} }

// Name returns the stable identifier for this collector.
func (n *Npm) Name() string { return "npm" }

// Available reports whether npm is on the PATH.
func (n *Npm) Available() bool {
	_, err := exec.LookPath("npm")
	return err == nil
}

// Collect runs npm list -g --json --depth=0 and returns parsed results.
func (n *Npm) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "npm", "list", "-g", "--json", "--depth=0")
	if err != nil {
		return nil, fmt.Errorf("npm list -g: %w", err)
	}
	return ParseNpmJSON(string(out)), nil
}

// npmOutput represents the top-level JSON from npm list -g --json.
type npmOutput struct {
	Dependencies map[string]npmDep `json:"dependencies"`
}

type npmDep struct {
	Version string `json:"version"`
}

// ParseNpmJSON parses the JSON output of npm list -g --json --depth=0.
func ParseNpmJSON(raw string) *Result {
	result := &Result{}
	if raw == "" {
		return result
	}

	var output npmOutput
	if err := json.Unmarshal([]byte(raw), &output); err != nil {
		result.Errs = append(result.Errs, CollectError{
			Collector: "npm",
			Line:      1,
			RawLine:   truncateRaw(raw),
			Err:       fmt.Errorf("json decode: %w", err),
		})
		return result
	}

	for name, dep := range output.Dependencies {
		if name == "" {
			continue
		}
		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        dep.Version,
			PackageManager: "npm",
			CPE23:          BuildCPE23WithTargetSW("", name, dep.Version, "node.js"),
		})
	}

	return result
}

// Compile-time interface check.
var _ Collector = (*Npm)(nil)
