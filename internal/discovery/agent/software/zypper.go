// zypper.go
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

type Zypper struct{}

func NewZypper() *Zypper { return &Zypper{} }

func (z *Zypper) Name() string { return "zypper" }

func (z *Zypper) Available() bool {
	_, err := exec.LookPath("zypper")
	return err == nil
}

func (z *Zypper) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "zypper", "se", "--installed-only", "--type=package", "-s")
	if err != nil {
		return nil, fmt.Errorf("zypper se: %w", err)
	}
	return ParseZypperOutput(string(out)), nil
}

// ParseZypperOutput parses the pipe-delimited table from zypper se --installed-only.
func ParseZypperOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" || !strings.Contains(line, "|") {
			continue
		}

		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "---") || strings.HasPrefix(trimmed, "S ") {
			continue
		}

		fields := strings.Split(line, "|")
		if len(fields) < 5 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "zypper",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected pipe-delimited table row"),
			})
			continue
		}

		name := strings.TrimSpace(fields[1])
		version := strings.TrimSpace(fields[3])
		arch := ""
		if len(fields) >= 6 {
			arch = strings.TrimSpace(fields[4])
		}

		if name == "" || name == "Name" {
			continue
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "zypper",
			Architecture:   arch,
			CPE23:          BuildCPE23WithArch("", name, version, arch),
		})
	}

	return result
}

var _ Collector = (*Zypper)(nil)
