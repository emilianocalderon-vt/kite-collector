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

// Gem collects installed Ruby gems using gem list.
type Gem struct{}

// NewGem returns a new Gem collector.
func NewGem() *Gem { return &Gem{} }

// Name returns the stable identifier for this collector.
func (g *Gem) Name() string { return "gem" }

// Available reports whether gem is on the PATH.
func (g *Gem) Available() bool {
	_, err := exec.LookPath("gem")
	return err == nil
}

// Collect runs gem list --local and returns parsed results.
func (g *Gem) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "gem", "list", "--local")
	if err != nil {
		return nil, fmt.Errorf("gem list: %w", err)
	}
	return ParseGemOutput(string(out)), nil
}

// ParseGemOutput parses the output of gem list --local.
// Lines have the format: "name (version1, version2, ...)".
// Only the first version is captured.
func ParseGemOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "***") {
			continue
		}

		openParen := strings.Index(line, " (")
		closeParen := strings.LastIndex(line, ")")
		if openParen < 0 || closeParen < 0 || closeParen <= openParen {
			result.Errs = append(result.Errs, CollectError{
				Collector: "gem",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'name (version, ...)' format"),
			})
			continue
		}

		name := line[:openParen]
		versionsStr := line[openParen+2 : closeParen]
		version := extractFirstGemVersion(versionsStr)

		if name == "" || version == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "gem",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("empty name or version"),
			})
			continue
		}

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "gem",
			CPE23:          BuildCPE23WithTargetSW("", name, version, "ruby"),
		})
	}

	return result
}

// extractFirstGemVersion returns the first non-default version from a
// comma-separated list like "2.5.11, default: 2.5.10".
func extractFirstGemVersion(s string) string {
	for _, part := range strings.Split(s, ", ") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "default: ")
		if part != "" {
			return part
		}
	}
	return ""
}

// Compile-time interface check.
var _ Collector = (*Gem)(nil)
