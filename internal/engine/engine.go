package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/audit"
	"github.com/vulnertrack/kite-collector/internal/classifier"
	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/dedup"
	"github.com/vulnertrack/kite-collector/internal/discovery"
	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
	"github.com/vulnertrack/kite-collector/internal/emitter"
	"github.com/vulnertrack/kite-collector/internal/metrics"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/policy"
	"github.com/vulnertrack/kite-collector/internal/posture"
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
			"host":              src.Host,
			"endpoint":          src.Endpoint,
			"site":              src.Site,
			"community":         src.Community,
		}
		configs[name] = m
	}

	slog.Info("engine: starting discovery", "scan_id", scanID)
	discovered, err := e.registry.DiscoverAll(ctx, configs)
	if err != nil {
		failResult := model.ScanResult{
			Status:     string(model.ScanStatusFailed),
			ErrorCount: 1,
		}
		_ = e.store.CompleteScanRun(ctx, scanID, failResult)
		return nil, fmt.Errorf("discovery: %w", err)
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
	var softwareCount, softwareErrors int
	if agentCfg, ok := configs["agent"]; ok {
		if cs, ok := agentCfg["collect_software"].(bool); ok && cs {
			if agentID := findAgentAssetID(assets); agentID != uuid.Nil {
				swReg := software.NewRegistry()
				swResult := swReg.Collect(ctx)
				softwareCount = len(swResult.Items)
				if len(swResult.Items) > 0 {
					for i := range swResult.Items {
						swResult.Items[i].AssetID = agentID
					}
					if swErr := e.store.UpsertSoftware(ctx, agentID, swResult.Items); swErr != nil {
						slog.Error("engine: failed to persist software",
							"error", swErr, "asset_id", agentID, "count", len(swResult.Items))
						softwareErrors++
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

	// Configuration audit phase: run enabled auditors on the agent asset.
	var findingsCount, postureCount int
	if cfg.Audit.Enabled {
		if agentID := findAgentAssetID(assets); agentID != uuid.Nil {
			var agentAsset model.Asset
			for _, a := range assets {
				if a.ID == agentID {
					agentAsset = a
					break
				}
			}

			auditReg := audit.NewRegistry()
			if cfg.Audit.SSH.Enabled {
				auditReg.Register(audit.NewSSH(cfg.Audit.SSH.ConfigPath))
			}
			if cfg.Audit.Firewall.Enabled {
				auditReg.Register(audit.NewFirewall())
			}
			if cfg.Audit.Kernel.Enabled {
				auditReg.Register(audit.NewKernel())
			}
			if cfg.Audit.Permissions.Enabled {
				auditReg.Register(audit.NewPermissions(cfg.Audit.Permissions.Paths))
			}
			if cfg.Audit.Service.Enabled {
				auditReg.Register(audit.NewService(cfg.Audit.Service.CriticalPorts))
			}

			findings, auditErr := auditReg.AuditAll(ctx, agentAsset)
			if auditErr != nil {
				slog.Warn("engine: audit phase failed", "error", auditErr)
			}
			if len(findings) > 0 {
				for i := range findings {
					findings[i].ScanRunID = scanID
				}
				if fErr := e.store.InsertFindings(ctx, findings); fErr != nil {
					slog.Error("engine: failed to persist findings", "error", fErr, "count", len(findings))
				} else {
					findingsCount = len(findings)
					slog.Info("engine: audit complete", "findings", findingsCount)
				}

				// Posture analysis: evaluate CWE→CAPEC mappings.
				if cfg.Posture.Enabled {
					assessments := posture.Evaluate(findings, agentID, scanID)
					if len(assessments) > 0 {
						if pErr := e.store.InsertPostureAssessments(ctx, assessments); pErr != nil {
							slog.Error("engine: failed to persist posture assessments",
								"error", pErr, "count", len(assessments))
						} else {
							postureCount = len(assessments)
							slog.Info("engine: posture analysis complete", "assessments", postureCount)
						}
					}
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
		Status:          string(model.ScanStatusCompleted),
		TotalAssets:     totalKnown,
		NewAssets:       dedupResult.NewCount,
		UpdatedAssets:   dedupResult.UpdatedCount,
		StaleAssets:     len(staleAssets),
		EventsEmitted:  len(events),
		SoftwareCount:   softwareCount,
		SoftwareErrors:  softwareErrors,
		FindingsCount:   findingsCount,
		PostureCount:    postureCount,
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
