package config

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the top-level configuration structure.
type Config struct {
	Discovery      DiscoveryConfig      `mapstructure:"discovery"`
	Classification ClassificationConfig `mapstructure:"classification"`
	Streaming      StreamingConfig      `mapstructure:"streaming"`
	Postgres       PostgresConfig       `mapstructure:"postgres"`
	LogLevel       string               `mapstructure:"log_level"`
	OutputFormat   string               `mapstructure:"output_format"`
	DataDir        string               `mapstructure:"data_dir"`
	StaleThreshold string               `mapstructure:"stale_threshold"` // duration string like "168h"
	Metrics        MetricsConfig        `mapstructure:"metrics"`
}

// DiscoveryConfig holds configuration for all discovery sources.
type DiscoveryConfig struct {
	Sources map[string]SourceConfig `mapstructure:"sources"`
}

// SourceConfig holds configuration for a single discovery source.
type SourceConfig struct {
	Timeout           string   `mapstructure:"timeout"`
	Scope             []string `mapstructure:"scope"`
	Regions           []string `mapstructure:"regions"`
	AssumeRole        string   `mapstructure:"assume_role"`
	Project           string   `mapstructure:"project"`
	SubscriptionID    string   `mapstructure:"subscription_id"`
	TCPPorts          []int    `mapstructure:"tcp_ports"`
	MaxConcurrent     int      `mapstructure:"max_concurrent"`
	Enabled           bool     `mapstructure:"enabled"`
	CollectSoftware   bool     `mapstructure:"collect_software"`
	CollectInterfaces bool     `mapstructure:"collect_interfaces"`
}

// ClassificationConfig holds authorization and managed-status classification settings.
type ClassificationConfig struct {
	Authorization AuthorizationConfig `mapstructure:"authorization"`
	Managed       ManagedConfig       `mapstructure:"managed"`
}

// AuthorizationConfig controls how assets are matched against an allowlist.
type AuthorizationConfig struct {
	AllowlistFile string   `mapstructure:"allowlist_file"`
	MatchFields   []string `mapstructure:"match_fields"`
}

// ManagedConfig defines which controls must be present for an asset to be
// considered "managed".
type ManagedConfig struct {
	RequiredControls []string `mapstructure:"required_controls"`
}

// MetricsConfig configures the Prometheus metrics endpoint.
type MetricsConfig struct {
	Listen  string `mapstructure:"listen"`
	Enabled bool   `mapstructure:"enabled"`
}

// StreamingConfig configures the continuous streaming agent mode.
type StreamingConfig struct {
	Interval string     `mapstructure:"interval"` // duration string like "6h"
	OTLP     OTLPConfig `mapstructure:"otlp"`
}

// OTLPConfig configures the OTLP event emitter.
type OTLPConfig struct {
	Endpoint string    `mapstructure:"endpoint"`
	Protocol string    `mapstructure:"protocol"` // "grpc" or "http"
	TLS      TLSConfig `mapstructure:"tls"`
}

// TLSConfig holds TLS certificate paths.
type TLSConfig struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
	CAFile   string `mapstructure:"ca_file"`
	Enabled  bool   `mapstructure:"enabled"`
}

// PostgresConfig configures the PostgreSQL backend for streaming mode.
type PostgresConfig struct {
	DSN string `mapstructure:"dsn"`
}

// Load reads configuration from a YAML file at path, applies defaults, and
// binds environment variables with the "KITE" prefix.  Environment variables
// use underscores as separators (e.g. KITE_LOG_LEVEL).
func Load(path string) (*Config, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("log_level", "info")
	v.SetDefault("output_format", "table")
	v.SetDefault("data_dir", "./data")
	v.SetDefault("stale_threshold", "168h")
	v.SetDefault("discovery.sources.agent.enabled", true)
	v.SetDefault("discovery.sources.agent.collect_software", true)
	v.SetDefault("discovery.sources.agent.collect_interfaces", true)
	v.SetDefault("metrics.enabled", false)
	v.SetDefault("metrics.listen", ":9090")
	v.SetDefault("streaming.interval", "6h")
	v.SetDefault("streaming.otlp.protocol", "grpc")

	// Environment variable binding
	v.SetEnvPrefix("KITE")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Read config file when a path is provided
	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, err
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// StaleThresholdDuration parses the StaleThreshold string into a
// time.Duration.  If the string is empty or invalid, it falls back to 168h
// (7 days).
func (c *Config) StaleThresholdDuration() time.Duration {
	if c.StaleThreshold == "" {
		return 168 * time.Hour
	}
	d, err := time.ParseDuration(c.StaleThreshold)
	if err != nil {
		return 168 * time.Hour
	}
	return d
}

// StreamingInterval parses the Streaming.Interval string into a
// time.Duration. Falls back to 6h if empty or invalid.
func (c *Config) StreamingInterval() time.Duration {
	if c.Streaming.Interval == "" {
		return 6 * time.Hour
	}
	d, err := time.ParseDuration(c.Streaming.Interval)
	if err != nil {
		return 6 * time.Hour
	}
	return d
}

// IsSourceEnabled reports whether the named discovery source exists in the
// configuration and has Enabled set to true.
func (c *Config) IsSourceEnabled(name string) bool {
	src, ok := c.Discovery.Sources[name]
	if !ok {
		return false
	}
	return src.Enabled
}

// SourceCfg returns the SourceConfig for the given source name.  If the
// source does not exist, a zero-value SourceConfig is returned.
func (c *Config) SourceCfg(name string) SourceConfig {
	return c.Discovery.Sources[name]
}
