package software

import (
	"context"
	"log/slog"
	"sync"

	"golang.org/x/sync/errgroup"
)

// Registry manages software collectors and runs available ones in parallel.
type Registry struct {
	collectors []Collector
}

// NewRegistry returns a Registry pre-loaded with all known collectors.
func NewRegistry() *Registry {
	return &Registry{
		collectors: []Collector{
			// Linux
			NewDpkg(),
			NewPacman(),
			NewRPM(),
			// Phase 1 — OS package managers
			NewBrew(),
			NewAPK(),
			NewChocolatey(),
			NewWinget(),
			// Phase 2 — Universal
			NewSnap(),
			NewFlatpak(),
			NewScoop(),
			NewNix(),
			// Phase 2 — AUR
			NewYay(),
			// Phase 2 — Language
			NewPip(),
			NewPipx(),
			NewNpm(),
			NewPnpm(),
			NewGem(),
			NewCargo(),
			// Phase 3 — OS (RFC-0058)
			NewDnf(),
			NewZypper(),
			NewFreeBSDPkg(),
			NewPortage(),
			NewXbps(),
			NewOpkg(),
			NewPkgsrc(),
			NewMacPorts(),
			// Phase 3 — Language (RFC-0058)
			NewComposer(),
			NewConda(),
			NewGoMod(),
			NewNuGet(),
			NewYarn(),
			NewBun(),
			NewMaven(),
			NewMamba(),
			// Phase 3 — Additional Language (RFC-0058)
			NewCocoaPods(),
			NewSwiftPM(),
			NewPub(),
			NewHex(),
			NewCPAN(),
			NewLuaRocks(),
			NewCRAN(),
			NewJuliaPkg(),
			NewCabal(),
			// Phase 3 — Scientific / C++ (RFC-0058)
			NewVcpkg(),
			NewConan(),
			NewSpack(),
			NewGuix(),
		},
	}
}

// Register adds a collector. Primarily useful for testing.
func (r *Registry) Register(c Collector) {
	r.collectors = append(r.collectors, c)
}

// Collect runs all available collectors in parallel, merges their results,
// and returns a single aggregated Result. Collectors whose Available()
// returns false are skipped. Fatal errors from individual collectors are
// logged but do not abort others.
func (r *Registry) Collect(ctx context.Context) *Result {
	merged := &Result{}

	var available []Collector
	for _, c := range r.collectors {
		if c.Available() {
			available = append(available, c)
			slog.Info("software: collector available", "name", c.Name())
		} else {
			slog.Debug("software: collector not available", "name", c.Name())
		}
	}

	if len(available) == 0 {
		return merged
	}

	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)

	for _, c := range available {
		g.Go(func() error {
			res, err := c.Collect(gctx)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				slog.Warn("software: collector failed",
					"name", c.Name(), "error", err)
				merged.Errs = append(merged.Errs, CollectError{
					Collector: c.Name(),
					Err:       err,
				})
				return nil // don't abort other collectors
			}

			merged.Merge(res)
			slog.Info("software: collector completed",
				"name", c.Name(),
				"packages", len(res.Items),
				"errors", res.TotalErrors(),
			)

			return nil
		})
	}

	_ = g.Wait()
	return merged
}
