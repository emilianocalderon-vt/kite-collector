// opkg.go
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

type Opkg struct{}

func NewOpkg() *Opkg { return &Opkg{} }

func (o *Opkg) Name() string { return "opkg" }

func (o *Opkg) Available() bool {
	_, err := exec.LookPath("opkg")
	return err == nil
}

func (o *Opkg) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "opkg", "list-installed")
	if err != nil {
		return nil, fmt.Errorf("opkg list-installed: %w", err)
	}
	return ParseOpkgOutput(string(out)), nil
}

// ParseOpkgOutput parses the output of opkg list-installed.
// Each line is "name - version".
func ParseOpkgOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " - ", 2)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "opkg",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'name - version' format"),
			})
			continue
		}

		name := parts[0]
		version := parts[1]

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "opkg",
			CPE23:          BuildCPE23("", name, version),
		})
	}

	return result
}

var _ Collector = (*Opkg)(nil)
