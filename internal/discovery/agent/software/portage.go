// portage.go
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

type Portage struct{}

func NewPortage() *Portage { return &Portage{} }

func (p *Portage) Name() string { return "portage" }

func (p *Portage) Available() bool {
	_, err := exec.LookPath("qlist")
	return err == nil
}

func (p *Portage) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "qlist", "-Iv")
	if err != nil {
		return nil, fmt.Errorf("qlist -Iv: %w", err)
	}
	return ParsePortageOutput(string(out)), nil
}

// ParsePortageOutput parses the output of qlist -Iv.
// Each line is "category/name-version".
func ParsePortageOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		idx := strings.Index(line, "/")
		if idx <= 0 || idx >= len(line)-1 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "portage",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'category/name-version' format"),
			})
			continue
		}

		nameVer := line[idx+1:]
		name, version := splitNameVersion(nameVer)
		if name == "" || version == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "portage",
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
			PackageManager: "portage",
			CPE23:          BuildCPE23("", name, version),
		})
	}

	return result
}

var _ Collector = (*Portage)(nil)
