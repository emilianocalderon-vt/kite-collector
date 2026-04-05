package classifier

import (
	"strings"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Manager determines whether an asset satisfies the organisation's required
// security controls (e.g. EDR agent, configuration management).
type Manager struct {
	requiredControls []string
}

// NewManager creates a Manager that checks for the given required controls.
func NewManager(requiredControls []string) *Manager {
	return &Manager{requiredControls: requiredControls}
}

// EvaluateWithSoftware determines managed state by checking if ALL required
// controls are present in the installed software list. A control matches if
// any installed software name contains the control string (case-insensitive).
//
// Rules (per guidelines 3.2):
//   - Empty requiredControls = opt-in, return "unknown"
//   - All required controls present = "managed"
//   - Any required control missing = "unmanaged"
func (m *Manager) EvaluateWithSoftware(asset model.Asset, software []model.InstalledSoftware) model.ManagedState {
	if len(m.requiredControls) == 0 {
		return model.ManagedUnknown
	}

	for _, control := range m.requiredControls {
		found := false
		controlLower := strings.ToLower(control)
		for _, sw := range software {
			if strings.Contains(strings.ToLower(sw.SoftwareName), controlLower) {
				found = true
				break
			}
		}
		if !found {
			return model.ManagedUnmanaged
		}
	}
	return model.ManagedManaged
}

// Evaluate determines managed state without software data.
// When no software is available, falls back to Phase 1 behaviour:
//   - If no required controls are configured (empty list), the feature is
//     opt-in and we return "unknown".
//   - If controls are configured, we return "unmanaged" because no software
//     inventory is available to verify control presence.
func (m *Manager) Evaluate(asset model.Asset) model.ManagedState {
	if len(m.requiredControls) == 0 {
		return model.ManagedUnknown
	}
	return model.ManagedUnmanaged
}
