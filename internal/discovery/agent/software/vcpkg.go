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

type Vcpkg struct{}

func NewVcpkg() *Vcpkg { return &Vcpkg{} }

func (v *Vcpkg) Name() string { return "vcpkg" }

func (v *Vcpkg) Available() bool {
	_, err := exec.LookPath("vcpkg")
	return err == nil
}

func (v *Vcpkg) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "vcpkg", "list")
	if err != nil {
		return nil, fmt.Errorf("vcpkg list: %w", err)
	}
	return ParseVcpkgOutput(string(out)), nil
}

// ParseVcpkgOutput parses the output of vcpkg list.
// Each line is "name:triplet  version  description".
func ParseVcpkgOutput(raw string) *Result {
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
				Collector: "vcpkg",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'name:triplet version' format"),
			})
			continue
		}

		nameTriplet := fields[0]
		version := fields[1]

		// Strip version suffixes like "#1".
		if idx := strings.IndexByte(version, '#'); idx > 0 {
			version = version[:idx]
		}

		name := nameTriplet
		arch := ""
		if idx := strings.IndexByte(nameTriplet, ':'); idx > 0 {
			name = nameTriplet[:idx]
			arch = nameTriplet[idx+1:]
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "vcpkg",
			Architecture:   arch,
			CPE23:          BuildCPE23WithTargetSW("", name, version, "cpp"),
		})
	}

	return result
}

var _ Collector = (*Vcpkg)(nil)
