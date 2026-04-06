package software

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Pipx collects installed Python CLI tools using pipx.
type Pipx struct{}

// NewPipx returns a new Pipx collector.
func NewPipx() *Pipx { return &Pipx{} }

// Name returns the stable identifier for this collector.
func (p *Pipx) Name() string { return "pipx" }

// Available reports whether pipx is on the PATH.
func (p *Pipx) Available() bool {
	_, err := exec.LookPath("pipx")
	return err == nil
}

// Collect runs pipx list --json and returns parsed results.
func (p *Pipx) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "pipx", "list", "--json")
	if err != nil {
		return nil, fmt.Errorf("pipx list --json: %w", err)
	}
	return ParsePipxJSON(string(out)), nil
}

// pipxOutput represents the top-level JSON from pipx list --json.
type pipxOutput struct {
	Venvs map[string]pipxVenv `json:"venvs"`
}

type pipxVenv struct {
	Metadata pipxMetadata `json:"metadata"`
}

type pipxMetadata struct {
	MainPackage pipxMainPackage `json:"main_package"`
}

type pipxMainPackage struct {
	Package        string `json:"package"`
	PackageVersion string `json:"package_version"`
}

// ParsePipxJSON parses the JSON output of pipx list --json.
func ParsePipxJSON(raw string) *Result {
	result := &Result{}
	if raw == "" {
		return result
	}

	var output pipxOutput
	if err := json.Unmarshal([]byte(raw), &output); err != nil {
		result.Errs = append(result.Errs, CollectError{
			Collector: "pipx",
			Line:      1,
			RawLine:   truncateRaw(raw),
			Err:       fmt.Errorf("json decode: %w", err),
		})
		return result
	}

	for _, venv := range output.Venvs {
		pkg := venv.Metadata.MainPackage
		if pkg.Package == "" {
			continue
		}
		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   pkg.Package,
			Version:        pkg.PackageVersion,
			PackageManager: "pipx",
			CPE23:          BuildCPE23WithTargetSW("", pkg.Package, pkg.PackageVersion, "python"),
		})
	}

	return result
}

// Compile-time interface check.
var _ Collector = (*Pipx)(nil)
