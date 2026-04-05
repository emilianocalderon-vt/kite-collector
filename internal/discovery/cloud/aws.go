package cloud

import (
	"context"
	"log/slog"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// AWS implements discovery.Source by listing EC2 instances across one or more
// AWS regions. It supports cross-account discovery via STS AssumeRole.
//
// This is a stub implementation that documents the expected configuration
// contract. A future version will integrate the AWS SDK for Go v2.
type AWS struct{}

// NewAWS returns a new AWS discovery source.
func NewAWS() *AWS {
	return &AWS{}
}

// Name returns the stable identifier for this source.
func (a *AWS) Name() string { return "aws_ec2" }

// Discover lists EC2 instances in the configured regions and returns them
// as assets. In the current stub implementation no cloud SDK calls are made.
//
// Supported config keys:
//
//	regions     – []any of AWS region strings (e.g. ["us-east-1", "eu-west-1"])
//	assume_role – string ARN of the IAM role to assume for cross-account access
func (a *AWS) Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error) {
	regions := toStringSlice(cfg["regions"])
	role := toString(cfg["assume_role"])

	slog.Info("aws_ec2: starting discovery",
		"regions", regions,
		"assume_role", role,
	)

	slog.Info("aws_ec2: cloud discovery not yet implemented, requires cloud SDK")

	return nil, nil
}

// ensure AWS satisfies the discovery.Source interface at compile time.
var _ interface {
	Name() string
	Discover(ctx context.Context, cfg map[string]any) ([]model.Asset, error)
} = (*AWS)(nil)
