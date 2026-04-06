// xbps.go
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

type Xbps struct{}

func NewXbps() *Xbps { return &Xbps{} }

func (x *Xbps) Name() string { return "xbps" }

func (x *Xbps) Available() bool {
	_, err := exec.LookPath("xbps-query")
	return err == nil
}

func (x *Xbps) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "xbps-query", "-l")
	if err != nil {
		return nil, fmt.Errorf("xbps-query -l: %w", err)
	}
	return ParseXbpsOutput(string(out)), nil
}

// ParseXbpsOutput parses the output of xbps-query -l.
// Each line is "ii name-version  description".
func ParseXbpsOutput(raw string) *Result {
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
				Collector: "xbps",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'ii name-version description' format"),
			})
			continue
		}

		token := fields[1]
		name, version := splitNameVersion(token)
		if name == "" || version == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "xbps",
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
			PackageManager: "xbps",
			CPE23:          BuildCPE23("", name, version),
		})
	}

	return result
}

var _ Collector = (*Xbps)(nil)
