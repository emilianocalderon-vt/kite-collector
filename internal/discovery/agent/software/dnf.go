// dnf.go
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

// Dnf collects installed packages using dnf on RHEL/Fedora systems.
type Dnf struct{}

func NewDnf() *Dnf { return &Dnf{} }

func (d *Dnf) Name() string { return "dnf" }

func (d *Dnf) Available() bool {
	_, err := exec.LookPath("dnf")
	return err == nil
}

func (d *Dnf) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "dnf", "list", "installed", "--quiet")
	if err != nil {
		return nil, fmt.Errorf("dnf list installed: %w", err)
	}
	return ParseDnfOutput(string(out)), nil
}

// ParseDnfOutput parses the output of dnf list installed --quiet.
// Each line has the format "name.arch  version-release  @repo".
func ParseDnfOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "dnf",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'name.arch version repo' format"),
			})
			continue
		}

		nameArch := fields[0]
		version := fields[1]

		name := nameArch
		arch := ""
		if idx := strings.LastIndex(nameArch, "."); idx > 0 {
			name = nameArch[:idx]
			arch = nameArch[idx+1:]
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "dnf",
			Architecture:   arch,
			CPE23:          BuildCPE23WithArch("", name, version, arch),
		})
	}

	return result
}

var _ Collector = (*Dnf)(nil)
