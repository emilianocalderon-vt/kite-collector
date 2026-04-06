package software

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Pnpm collects globally installed Node.js packages using pnpm.
type Pnpm struct{}

// NewPnpm returns a new Pnpm collector.
func NewPnpm() *Pnpm { return &Pnpm{} }

// Name returns the stable identifier for this collector.
func (p *Pnpm) Name() string { return "pnpm" }

// Available reports whether pnpm is on the PATH.
func (p *Pnpm) Available() bool {
	_, err := exec.LookPath("pnpm")
	return err == nil
}

// Collect runs pnpm list -g --json and returns parsed results.
func (p *Pnpm) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "pnpm", "list", "-g", "--json")
	if err != nil {
		return nil, fmt.Errorf("pnpm list -g: %w", err)
	}
	return ParsePnpmJSON(string(out)), nil
}

// pnpmProject represents one element of the pnpm list -g --json output.
type pnpmProject struct {
	Dependencies map[string]pnpmDep `json:"dependencies"`
}

type pnpmDep struct {
	Version string `json:"version"`
}

// ParsePnpmJSON parses the JSON output of pnpm list -g --json.
// The output is an array of project objects; global packages are in the
// first element's dependencies.
func ParsePnpmJSON(raw string) *Result {
	result := &Result{}
	if raw == "" {
		return result
	}

	var projects []pnpmProject
	if err := json.Unmarshal([]byte(raw), &projects); err != nil {
		result.Errs = append(result.Errs, CollectError{
			Collector: "pnpm",
			Line:      1,
			RawLine:   truncateRaw(raw),
			Err:       fmt.Errorf("json decode: %w", err),
		})
		return result
	}

	if len(projects) == 0 {
		return result
	}

	for name, dep := range projects[0].Dependencies {
		if name == "" {
			continue
		}
		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        dep.Version,
			PackageManager: "pnpm",
			CPE23:          BuildCPE23WithTargetSW("", name, dep.Version, "node.js"),
		})
	}

	return result
}

// Compile-time interface check.
var _ Collector = (*Pnpm)(nil)
