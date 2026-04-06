package software

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

type Spack struct{}

func NewSpack() *Spack { return &Spack{} }

func (s *Spack) Name() string { return "spack" }

func (s *Spack) Available() bool {
	_, err := exec.LookPath("spack")
	return err == nil
}

func (s *Spack) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "spack", "find", "--json")
	if err != nil {
		return nil, fmt.Errorf("spack find: %w", err)
	}
	return ParseSpackJSON(string(out)), nil
}

type spackSpec struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ParseSpackJSON parses the JSON output of spack find --json.
func ParseSpackJSON(raw string) *Result {
	result := &Result{}
	if raw == "" {
		return result
	}

	var specs []spackSpec
	if err := json.Unmarshal([]byte(raw), &specs); err != nil {
		result.Errs = append(result.Errs, CollectError{
			Collector: "spack",
			Line:      1,
			RawLine:   truncateRaw(raw),
			Err:       fmt.Errorf("json decode: %w", err),
		})
		return result
	}

	for _, spec := range specs {
		if spec.Name == "" {
			continue
		}
		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   spec.Name,
			Version:        spec.Version,
			PackageManager: "spack",
			CPE23:          BuildCPE23("", spec.Name, spec.Version),
		})
	}

	return result
}

var _ Collector = (*Spack)(nil)
