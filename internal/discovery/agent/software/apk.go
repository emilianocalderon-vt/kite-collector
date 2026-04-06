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

// APK collects installed packages using apk on Alpine Linux.
type APK struct{}

// NewAPK returns a new APK collector.
func NewAPK() *APK { return &APK{} }

// Name returns the stable identifier for this collector.
func (a *APK) Name() string { return "apk" }

// Available reports whether apk is on the PATH.
func (a *APK) Available() bool {
	_, err := exec.LookPath("apk")
	return err == nil
}

// Collect runs apk list --installed and returns parsed results.
func (a *APK) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "apk", "list", "--installed")
	if err != nil {
		return nil, fmt.Errorf("apk list --installed: %w", err)
	}
	return ParseAPKOutput(string(out)), nil
}

// ParseAPKOutput parses the raw output of apk list --installed.
// Each line is expected as "name-version arch {origin} (license)".
func ParseAPKOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "WARNING:") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "apk",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'name-version arch {origin} (license)' format"),
			})
			continue
		}

		name, version := splitNameVersion(parts[0])
		if name == "" || version == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "apk",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("cannot split package name and version"),
			})
			continue
		}

		arch := parts[1]

		origin := ""
		for _, p := range parts[2:] {
			if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
				origin = p[1 : len(p)-1]
				break
			}
		}

		vendor := origin

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   name,
			Vendor:         vendor,
			Version:        version,
			PackageManager: "apk",
			Architecture:   arch,
			CPE23:          BuildCPE23WithArch(vendor, name, version, arch),
		})
	}

	return result
}

// splitNameVersion splits a "name-version" string at the first hyphen
// followed by a digit. Returns (s, "") if no such boundary exists.
func splitNameVersion(s string) (string, string) {
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '-' && s[i+1] >= '0' && s[i+1] <= '9' {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}

// Compile-time interface check.
var _ Collector = (*APK)(nil)
