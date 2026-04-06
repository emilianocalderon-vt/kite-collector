// pkgsrc.go
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

type Pkgsrc struct{}

func NewPkgsrc() *Pkgsrc { return &Pkgsrc{} }

func (p *Pkgsrc) Name() string { return "pkgsrc" }

func (p *Pkgsrc) Available() bool {
	_, err := exec.LookPath("pkg_info")
	return err == nil
}

func (p *Pkgsrc) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "pkg_info")
	if err != nil {
		return nil, fmt.Errorf("pkg_info: %w", err)
	}
	return ParsePkgsrcOutput(string(out)), nil
}

// ParsePkgsrcOutput parses the output of pkg_info.
// Each line is "name-version  description".
func ParsePkgsrcOutput(raw string) *Result {
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
		if len(fields) == 0 {
			continue
		}

		token := fields[0]
		name, version := splitNameVersion(token)
		if name == "" || version == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "pkgsrc",
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
			PackageManager: "pkgsrc",
			CPE23:          BuildCPE23("", name, version),
		})
	}

	return result
}

var _ Collector = (*Pkgsrc)(nil)
