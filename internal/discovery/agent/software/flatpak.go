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

// Flatpak collects installed applications using Flatpak on Linux.
type Flatpak struct{}

// NewFlatpak returns a new Flatpak collector.
func NewFlatpak() *Flatpak { return &Flatpak{} }

// Name returns the stable identifier for this collector.
func (f *Flatpak) Name() string { return "flatpak" }

// Available reports whether flatpak is on the PATH.
func (f *Flatpak) Available() bool {
	_, err := exec.LookPath("flatpak")
	return err == nil
}

// Collect runs flatpak list --app and returns parsed results.
func (f *Flatpak) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "flatpak", "list", "--app", "--columns=application,version,origin")
	if err != nil {
		return nil, fmt.Errorf("flatpak list: %w", err)
	}
	return ParseFlatpakOutput(string(out)), nil
}

// ParseFlatpakOutput parses the tab-separated output of
// flatpak list --app --columns=application,version,origin.
func ParseFlatpakOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 2 || parts[0] == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "flatpak",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected tab-separated 'application\\tversion[\\torigin]' format"),
			})
			continue
		}

		appID := parts[0]
		version := parts[1]

		vendor, product := parseFlatpakID(appID)

		result.Items = append(result.Items, model.InstalledSoftware{
			ID:             uuid.Must(uuid.NewV7()),
			SoftwareName:   product,
			Vendor:         vendor,
			Version:        version,
			PackageManager: "flatpak",
			CPE23:          BuildCPE23(vendor, product, version),
		})
	}

	return result
}

// parseFlatpakID extracts vendor and product from a reverse-domain app ID
// like "org.mozilla.firefox" → ("mozilla", "firefox").
func parseFlatpakID(appID string) (vendor, product string) {
	segments := strings.Split(appID, ".")
	switch {
	case len(segments) >= 3:
		vendor = segments[1]
		product = segments[len(segments)-1]
	case len(segments) == 2:
		vendor = segments[0]
		product = segments[1]
	default:
		product = appID
	}
	return vendor, product
}

// Compile-time interface check.
var _ Collector = (*Flatpak)(nil)
