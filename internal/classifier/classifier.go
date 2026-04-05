package classifier

import (
	"github.com/google/uuid"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// Classifier orchestrates authorization and managed-state classification for
// discovered assets.
type Classifier struct {
	authorizer *Authorizer
	manager    *Manager
}

// New creates a Classifier backed by the given Authorizer and Manager.
func New(authorizer *Authorizer, manager *Manager) *Classifier {
	return &Classifier{
		authorizer: authorizer,
		manager:    manager,
	}
}

// ClassifyAll applies classification to every asset in the slice, updating
// each asset's IsAuthorized and IsManaged fields in place.  The (possibly
// mutated) slice is returned for convenience.
func (c *Classifier) ClassifyAll(assets []model.Asset) []model.Asset {
	for i := range assets {
		c.Classify(&assets[i])
	}
	return assets
}

// Classify sets the IsAuthorized and IsManaged fields on a single asset.
func (c *Classifier) Classify(asset *model.Asset) {
	asset.IsAuthorized = c.authorizer.Authorize(*asset)
	asset.IsManaged = c.manager.Evaluate(*asset)
}

// ClassifyWithSoftware sets the IsAuthorized and IsManaged fields on a single
// asset, using the provided software inventory for managed-state evaluation.
// This enables Phase 2 classification where installed software is checked
// against required controls.
func (c *Classifier) ClassifyWithSoftware(asset *model.Asset, software []model.InstalledSoftware) {
	asset.IsAuthorized = c.authorizer.Authorize(*asset)
	asset.IsManaged = c.manager.EvaluateWithSoftware(*asset, software)
}

// ClassifyAllWithSoftware applies classification to every asset in the slice,
// using the provided software map to look up installed software by asset ID.
// Assets without an entry in the software map fall back to the Phase 1
// Evaluate method (no software data available).  The (possibly mutated) slice
// is returned for convenience.
func (c *Classifier) ClassifyAllWithSoftware(assets []model.Asset, softwareByAsset map[uuid.UUID][]model.InstalledSoftware) []model.Asset {
	for i := range assets {
		sw, ok := softwareByAsset[assets[i].ID]
		if ok {
			c.ClassifyWithSoftware(&assets[i], sw)
		} else {
			c.Classify(&assets[i])
		}
	}
	return assets
}
