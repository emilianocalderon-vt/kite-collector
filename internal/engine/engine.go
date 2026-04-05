package engine

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/classifier"
	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/dedup"
	"github.com/vulnertrack/kite-collector/internal/discovery"
	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
	"github.com/vulnertrack/kite-collector/internal/emitter"
	"github.com/vulnertrack/kite-collector/internal/metrics"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/policy"
	"github.com/vulnertrack/kite-collector/internal/store"
)

type Engine struct {
	store        store.Store
	registry     *discovery.Registry
	deduplicator *dedup.Deduplicator
	classifier   *classifier.Classifier
	emitter      emitter.Emitter
	policy       *policy.Engine
	metrics      *metrics.Metrics
}

func New(
	st store.Store,
	reg *discovery.Registry,
	dd *dedup.Deduplicator,
	cls *classifier.Classifier,
	em emitter.Emitter,
	pol *policy.Engine,
	met *metrics.Metrics,
) *Engine {
	return &Engine{
		store:        st,
		registry:     reg,
		deduplicator: dd,
		classifier:   cls,
		emitter:      em,
		policy:       pol,
		metrics:      met,
	}
}

func (e *Engine) Run(ctx context.Context, cfg *config.Config) (*model.ScanResult, error) {
	scanID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC()

	scopeJSON, _ := json.Marshal(cfg.Discovery.Sources)
	sourceNames := make([]string, 0, len(cfg.Discovery.Sources))
	for name := range cfg.Discovery.Sources {
		sourceNames = append(sourceNames, name)
	}
	sourcesJSON, _ := json.Marshal(sourceNames)

	scanRun := model.ScanRun{
		ID:               scanID,
		StartedAt:        now,
		Status:           model.ScanStatusRunning,
		ScopeConfig:      string(scopeJSON),
		DiscoverySources: string(sourcesJSON),
	}
	if err := e.store.CreateScanRun(ctx, scanRun); err != nil {
		return nil, err
	}

	configs := make(map[string]map[string]any)
	for name, src := range cfg.Discovery.Sources {
		m := map[string]any{
			"scope":              src.Scope,
			"tcp_ports":          src.TCPPorts,
			"timeout":            src.Timeout,
			"max_concurrent":     src.MaxConcurrent,
			"collect_software":   src.CollectSoftware,
			"collect_interfaces": src.CollectInterfaces,
		}
		configs[name] = m
	}

	slog.Info("engine: starting discovery", "scan_id", scanID)
	discovered, err := e.registry.DiscoverAll(ctx, configs)
	if err != nil {
		return nil, err
	}
	slog.Info("engine: discovery complete", "raw_assets", len(discovered))

	dedupResult, err := e.deduplicator.Deduplicate(ctx, discovered)
	if err != nil {
		return nil, err
	}

	assets := e.classifier.ClassifyAll(dedupResult.Assets)

	inserted, updated, err := e.store.UpsertAssets(ctx, assets)
	if err != nil {
		return nil, err
	}
	slog.Info("engine: persisted assets", "inserted", inserted, "updated", updated)

	// Collect and persist installed software for the agent asset.
	if agentCfg, ok := configs["agent"]; ok {
		if cs, ok := agentCfg["collect_software"].(bool); ok && cs {
			if agentID := findAgentAssetID(assets); agentID != uuid.Nil {
				swReg := software.NewRegistry()
				swResult := swReg.Collect(ctx)
				if len(swResult.Items) > 0 {
					for i := range swResult.Items {
						swResult.Items[i].AssetID = agentID
					}
					if swErr := e.store.UpsertSoftware(ctx, agentID, swResult.Items); swErr != nil {
						slog.Warn("engine: failed to persist software", "error", swErr)
					} else {
						slog.Info("engine: persisted software",
							"asset_id", agentID,
							"count", len(swResult.Items),
							"parse_errors", swResult.TotalErrors(),
						)
					}
				}
				if swResult.HasErrors() {
					slog.Warn("engine: software parse errors", "count", swResult.TotalErrors())
				}
			}
		}
	}

	staleAssets, err := e.store.GetStaleAssets(ctx, cfg.StaleThresholdDuration())
	if err != nil {
		slog.Warn("engine: failed to detect stale assets", "error", err)
		staleAssets = nil
	}

	var events []model.AssetEvent
	for i := range assets {
		var evtType model.EventType
		if assets[i].FirstSeenAt.Equal(assets[i].LastSeenAt) {
			evtType = model.EventAssetDiscovered
		} else {
			evtType = model.EventAssetUpdated
		}
		severity := e.policy.EvaluateSeverity(assets[i])
		if assets[i].IsAuthorized == model.AuthorizationUnauthorized {
			evtType = model.EventUnauthorizedAssetDetected
		} else if assets[i].IsManaged == model.ManagedUnmanaged {
			evtType = model.EventUnmanagedAssetDetected
		}
		events = append(events, model.AssetEvent{
			ID:        uuid.Must(uuid.NewV7()),
			EventType: evtType,
			AssetID:   assets[i].ID,
			ScanRunID: scanID,
			Severity:  severity,
			Timestamp: time.Now().UTC(),
		})
	}

	for i := range staleAssets {
		events = append(events, model.AssetEvent{
			ID:        uuid.Must(uuid.NewV7()),
			EventType: model.EventAssetNotSeen,
			AssetID:   staleAssets[i].ID,
			ScanRunID: scanID,
			Severity:  model.SeverityMedium,
			Timestamp: time.Now().UTC(),
		})
	}

	if len(events) > 0 {
		if err := e.store.InsertEvents(ctx, events); err != nil {
			slog.Warn("engine: failed to persist events", "error", err)
		}
		if err := e.emitter.EmitBatch(ctx, events); err != nil {
			slog.Warn("engine: failed to emit events", "error", err)
		}
	}

	if e.metrics != nil {
		e.metrics.StaleAssets.Set(float64(len(staleAssets)))
	}

	allAssets, _ := e.store.ListAssets(ctx, store.AssetFilter{})
	totalKnown := len(allAssets)
	coveragePct := 0.0
	if totalKnown > 0 {
		coveragePct = float64(len(assets)) / float64(totalKnown) * 100.0
	}

	result := &model.ScanResult{
		TotalAssets:     totalKnown,
		NewAssets:       dedupResult.NewCount,
		UpdatedAssets:   dedupResult.UpdatedCount,
		StaleAssets:     len(staleAssets),
		EventsEmitted:  len(events),
		CoveragePercent: coveragePct,
	}

	if err := e.store.CompleteScanRun(ctx, scanID, *result); err != nil {
		slog.Warn("engine: failed to complete scan run", "error", err)
	}

	slog.Info("engine: scan complete",
		"total", result.TotalAssets,
		"new", result.NewAssets,
		"updated", result.UpdatedAssets,
		"stale", result.StaleAssets,
		"events", result.EventsEmitted,
	)

	return result, nil
}

// findAgentAssetID returns the ID of the first asset with DiscoverySource "agent".
func findAgentAssetID(assets []model.Asset) uuid.UUID {
	for _, a := range assets {
		if a.DiscoverySource == "agent" {
			return a.ID
		}
	}
	return uuid.Nil
}
