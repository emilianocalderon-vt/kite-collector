// freebsdpkg.go
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

// FreeBSDPkg collects installed packages using pkg on FreeBSD.
type FreeBSDPkg struct{}

func NewFreeBSDPkg() *FreeBSDPkg { return &FreeBSDPkg{} }

func (f *FreeBSDPkg) Name() string { return "freebsdpkg" }

func (f *FreeBSDPkg) Available() bool {
	_, err := exec.LookPath("pkg")
	return err == nil
}

func (f *FreeBSDPkg) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "pkg", "info", "-a")
	if err != nil {
		return nil, fmt.Errorf("pkg info -a: %w", err)
	}
	return ParseFreeBSDPkgOutput(string(out)), nil
}

// ParseFreeBSDPkgOutput parses the output of pkg info -a.
// Each line is "name-version  description".
func ParseFreeBSDPkgOutput(raw string) *Result {
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
				Collector: "freebsdpkg",
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
			PackageManager: "freebsdpkg",
			CPE23:          BuildCPE23("", name, version),
		})
	}

	return result
}

var _ Collector = (*FreeBSDPkg)(nil)
