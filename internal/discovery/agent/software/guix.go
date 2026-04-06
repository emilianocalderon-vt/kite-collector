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

type Guix struct{}

func NewGuix() *Guix { return &Guix{} }

func (g *Guix) Name() string { return "guix" }

func (g *Guix) Available() bool {
	_, err := exec.LookPath("guix")
	return err == nil
}

func (g *Guix) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "guix", "package", "--list-installed")
	if err != nil {
		return nil, fmt.Errorf("guix package --list-installed: %w", err)
	}
	return ParseGuixOutput(string(out)), nil
}

// ParseGuixOutput parses the tab-separated output of guix package --list-installed.
// Each line is "name\tversion\toutput\tpath".
func ParseGuixOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "\t", 4)
		if len(parts) < 2 || parts[0] == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "guix",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'name\\tversion\\t...' format"),
			})
			continue
		}

		name := parts[0]
		version := parts[1]

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "guix",
			CPE23:          BuildCPE23("", name, version),
		})
	}

	return result
}

var _ Collector = (*Guix)(nil)
