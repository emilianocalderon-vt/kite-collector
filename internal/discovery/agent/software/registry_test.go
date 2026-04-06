package software

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// ---------------------------------------------------------------------------
// Mock collectors
// ---------------------------------------------------------------------------

type availableCollector struct {
	name  string
	items []model.InstalledSoftware
	errs  []CollectError
}

func (c *availableCollector) Name() string   { return c.name }
func (c *availableCollector) Available() bool { return true }
func (c *availableCollector) Collect(_ context.Context) (*Result, error) {
	return &Result{Items: c.items, Errs: c.errs}, nil
}

type unavailableCollector struct {
	name string
}

func (c *unavailableCollector) Name() string   { return c.name }
func (c *unavailableCollector) Available() bool { return false }
func (c *unavailableCollector) Collect(_ context.Context) (*Result, error) {
	panic("should not be called")
}

type failingCollector struct {
	name string
}

func (c *failingCollector) Name() string   { return c.name }
func (c *failingCollector) Available() bool { return true }
func (c *failingCollector) Collect(_ context.Context) (*Result, error) {
	return nil, errors.New("simulated failure")
}

// Compile-time interface checks.
var _ Collector = (*availableCollector)(nil)
var _ Collector = (*unavailableCollector)(nil)
var _ Collector = (*failingCollector)(nil)

// ---------------------------------------------------------------------------
// Registry tests
// ---------------------------------------------------------------------------

func TestRegistry_Collect_RunsAvailableCollectors(t *testing.T) {
	r := &Registry{}
	r.Register(&availableCollector{
		name: "test",
		items: []model.InstalledSoftware{
			{ID: uuid.Must(uuid.NewV7()), SoftwareName: "pkg1", Version: "1.0"},
		},
	})

	result := r.Collect(context.Background())
	require.Len(t, result.Items, 1)
	assert.Equal(t, "pkg1", result.Items[0].SoftwareName)
}

func TestRegistry_Collect_SkipsUnavailable(t *testing.T) {
	r := &Registry{}
	r.Register(&unavailableCollector{name: "missing"})
	r.Register(&availableCollector{
		name:  "present",
		items: []model.InstalledSoftware{{ID: uuid.Must(uuid.NewV7()), SoftwareName: "ok", Version: "1"}},
	})

	result := r.Collect(context.Background())
	require.Len(t, result.Items, 1)
	assert.Equal(t, "ok", result.Items[0].SoftwareName)
}

func TestRegistry_Collect_AllUnavailable_ReturnsEmpty(t *testing.T) {
	r := &Registry{}
	r.Register(&unavailableCollector{name: "a"})
	r.Register(&unavailableCollector{name: "b"})

	result := r.Collect(context.Background())
	assert.Empty(t, result.Items)
	assert.Empty(t, result.Errs)
}

func TestRegistry_Collect_FailingCollectorDoesNotAbortOthers(t *testing.T) {
	r := &Registry{}
	r.Register(&failingCollector{name: "broken"})
	r.Register(&availableCollector{
		name:  "works",
		items: []model.InstalledSoftware{{ID: uuid.Must(uuid.NewV7()), SoftwareName: "good", Version: "1"}},
	})

	result := r.Collect(context.Background())
	require.Len(t, result.Items, 1)
	assert.Equal(t, "good", result.Items[0].SoftwareName)
	// The failing collector's error is captured.
	assert.True(t, result.HasErrors())
}

func TestRegistry_Collect_MergesResults(t *testing.T) {
	r := &Registry{}
	r.Register(&availableCollector{
		name:  "a",
		items: []model.InstalledSoftware{{ID: uuid.Must(uuid.NewV7()), SoftwareName: "pkgA", Version: "1"}},
	})
	r.Register(&availableCollector{
		name:  "b",
		items: []model.InstalledSoftware{{ID: uuid.Must(uuid.NewV7()), SoftwareName: "pkgB", Version: "2"}},
	})

	result := r.Collect(context.Background())
	require.Len(t, result.Items, 2)

	names := []string{result.Items[0].SoftwareName, result.Items[1].SoftwareName}
	assert.Contains(t, names, "pkgA")
	assert.Contains(t, names, "pkgB")
}

func TestRegistry_Collect_MergesErrors(t *testing.T) {
	r := &Registry{}
	r.Register(&availableCollector{
		name: "a",
		errs: []CollectError{{Collector: "a", Line: 1, Err: errors.New("e1")}},
	})
	r.Register(&availableCollector{
		name: "b",
		errs: []CollectError{{Collector: "b", Line: 2, Err: errors.New("e2")}},
	})

	result := r.Collect(context.Background())
	require.Len(t, result.Errs, 2)
}

func TestRegistry_Register(t *testing.T) {
	r := &Registry{}
	assert.Empty(t, r.collectors)

	r.Register(&availableCollector{name: "test"})
	assert.Len(t, r.collectors, 1)
}

func TestNewRegistry_ContainsAllCollectors(t *testing.T) {
	// RFC-0056 (18) + RFC-0058 OS (8) = 26 so far.
	// Update this list when adding new collectors.
	expected := []string{
		// Phase 0 — Linux
		"dpkg", "pacman", "rpm",
		// Phase 1 — OS package managers
		"brew", "apk", "chocolatey", "winget",
		// Phase 2 — Universal + AUR
		"snap", "flatpak", "scoop", "nix", "yay",
		// Phase 2 — Language
		"pip", "pipx", "npm", "pnpm", "gem", "cargo",
		// Phase 3 — OS (RFC-0058)
		"dnf", "zypper", "freebsdpkg", "portage",
		"xbps", "opkg", "pkgsrc", "macports",
	}

	r := NewRegistry()
	require.Len(t, r.collectors, len(expected),
		"NewRegistry() should return %d collectors (got %d). "+
			"If you added a new collector, update this test and the expected list.",
		len(expected), len(r.collectors))

	names := make(map[string]bool, len(r.collectors))
	for _, c := range r.collectors {
		names[c.Name()] = true
	}

	for _, name := range expected {
		assert.True(t, names[name],
			"collector %q missing from NewRegistry()", name)
	}
}
