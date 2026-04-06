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

type Conan struct{}

func NewConan() *Conan { return &Conan{} }

func (c *Conan) Name() string { return "conan" }

func (c *Conan) Available() bool {
	_, err := exec.LookPath("conan")
	return err == nil
}

func (c *Conan) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "conan", "list", "*:*")
	if err != nil {
		return nil, fmt.Errorf("conan list: %w", err)
	}
	return ParseConanOutput(string(out)), nil
}

// ParseConanOutput parses the structured text output of conan list.
// Lines matching "name/version" are extracted as packages.
func ParseConanOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0
	seen := make(map[string]bool)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Look for "name/version" pattern. Strip any trailing @... or #...
		idx := strings.Index(trimmed, "/")
		if idx <= 0 || idx >= len(trimmed)-1 {
			continue
		}

		name := trimmed[:idx]
		rest := trimmed[idx+1:]

		// Strip conan reference suffixes (@user/channel, #revision).
		if at := strings.IndexByte(rest, '@'); at > 0 {
			rest = rest[:at]
		}
		if hash := strings.IndexByte(rest, '#'); hash > 0 {
			rest = rest[:hash]
		}
		version := rest

		// Version must start with a digit.
		if len(version) == 0 || version[0] < '0' || version[0] > '9' {
			continue
		}

		key := name + "/" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Version:        version,
			PackageManager: "conan",
			CPE23:          BuildCPE23WithTargetSW("", name, version, "cpp"),
		})
	}

	if len(result.Items) == 0 && raw != "" && !strings.Contains(raw, "/") {
		result.Errs = append(result.Errs, CollectError{
			Collector: "conan",
			Line:      1,
			RawLine:   truncateRaw(raw),
			Err:       errors.New("no packages found in conan output"),
		})
	}

	return result
}

var _ Collector = (*Conan)(nil)
