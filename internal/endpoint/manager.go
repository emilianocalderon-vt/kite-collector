// Package endpoint manages connections to multiple backend endpoints with
// health checking, failover, and data routing.
package endpoint

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	kitev1 "github.com/vulnertrack/kite-collector/api/grpc/proto/kite/v1"
	"github.com/vulnertrack/kite-collector/internal/config"
)

// State represents the health state of an endpoint.
type State int

const (
	StateHealthy     State = iota // responding normally
	StateDegraded                 // intermittent failures
	StateUnreachable              // consistently failing
	StateUntrusted                // TOFU fingerprint mismatch
)

func (s State) String() string {
	switch s {
	case StateHealthy:
		return "healthy"
	case StateDegraded:
		return "degraded"
	case StateUnreachable:
		return "unreachable"
	case StateUntrusted:
		return "untrusted"
	default:
		return "unknown"
	}
}

// Endpoint holds the runtime state for a single backend connection.
type Endpoint struct {
	LastSeen             time.Time
	Client               kitev1.CollectorServiceClient
	Conn                 *grpc.ClientConn
	Config               config.EndpointConfig
	State                State
	consecutiveFailures  int
	consecutiveSuccesses int
	mu                   sync.RWMutex
}

// Info returns a snapshot of the endpoint state for display.
type Info struct {
	LastSeen time.Time
	Name     string
	Address  string
	State    string
	Routes   []string
	Priority int
}

// Manager coordinates connections to multiple backend endpoints.
type Manager struct {
	logger    *slog.Logger
	cancel    context.CancelFunc
	endpoints []*Endpoint
	mu        sync.RWMutex
}

// NewManager creates a manager for the given endpoint configurations.
// It establishes gRPC connections and starts health checking goroutines.
func NewManager(ctx context.Context, configs []config.EndpointConfig, logger *slog.Logger) (*Manager, error) {
	if logger == nil {
		logger = slog.Default()
	}

	m := &Manager{
		endpoints: make([]*Endpoint, 0, len(configs)),
		logger:    logger,
	}

	for _, cfg := range configs {
		ep, err := m.connect(cfg)
		if err != nil {
			logger.Warn("skipping endpoint — connection failed",
				"name", cfg.Name,
				"address", cfg.Address,
				"error", err,
			)
			// Add the endpoint as unreachable so it can be recovered later.
			m.endpoints = append(m.endpoints, &Endpoint{
				Config: cfg,
				State:  StateUnreachable,
			})
			continue
		}
		m.endpoints = append(m.endpoints, ep)
	}

	// Sort by priority (lower = higher priority).
	sort.Slice(m.endpoints, func(i, j int) bool {
		return m.endpoints[i].Config.Priority < m.endpoints[j].Config.Priority
	})

	// Start health checkers.
	hctx, hcancel := context.WithCancel(ctx)
	m.cancel = hcancel
	for _, ep := range m.endpoints {
		go m.healthLoop(hctx, ep)
	}

	return m, nil
}

// connect establishes a gRPC connection to the endpoint.
func (m *Manager) connect(cfg config.EndpointConfig) (*Endpoint, error) {
	opts := []grpc.DialOption{}

	var capture *TLSStateCapture

	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		tc, err := buildMTLSConfig(cfg.TLS)
		if err != nil {
			return nil, err
		}
		capture = NewTLSStateCapture(credentials.NewTLS(tc))
		opts = append(opts, grpc.WithTransportCredentials(capture))
	} else if cfg.TLS.Enabled {
		capture = NewTLSStateCapture(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13,
		}))
		opts = append(opts, grpc.WithTransportCredentials(capture))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		m.logger.Warn("endpoint has no TLS configured — insecure", "name", cfg.Name)
	}

	// Channel binding interceptors use the captured TLS state (nil-safe).
	opts = append(opts,
		grpc.WithUnaryInterceptor(ChannelBindingInterceptor(capture)),
		grpc.WithStreamInterceptor(ChannelBindingStreamInterceptor(capture)),
	)

	conn, err := grpc.NewClient(cfg.Address, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", cfg.Address, err)
	}

	return &Endpoint{
		Config:   cfg,
		Conn:     conn,
		Client:   kitev1.NewCollectorServiceClient(conn),
		State:    StateHealthy,
		LastSeen: time.Now(),
	}, nil
}

func buildMTLSConfig(tlsCfg config.TLSConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load mTLS keypair: %w", err)
	}

	tc := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	if tlsCfg.CAFile != "" {
		caPEM, readErr := os.ReadFile(tlsCfg.CAFile) // #nosec G304 — path from trusted config
		if readErr != nil {
			return nil, fmt.Errorf("read CA file: %w", readErr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("CA file contains no valid certificates")
		}
		tc.RootCAs = pool
	}

	return tc, nil
}

// ForRoute returns the best healthy endpoint for the given route type.
// If no healthy endpoint is available, it returns nil.
func (m *Manager) ForRoute(route string) *Endpoint {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, ep := range m.endpoints {
		ep.mu.RLock()
		state := ep.State
		ep.mu.RUnlock()

		if state != StateHealthy && state != StateDegraded {
			continue
		}
		for _, r := range ep.Config.Routes {
			if r == route {
				return ep
			}
		}
	}
	return nil
}

// AllForRoute returns all healthy endpoints that accept the given route,
// ordered by priority.
func (m *Manager) AllForRoute(route string) []*Endpoint {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*Endpoint
	for _, ep := range m.endpoints {
		ep.mu.RLock()
		state := ep.State
		ep.mu.RUnlock()

		if state != StateHealthy && state != StateDegraded {
			continue
		}
		for _, r := range ep.Config.Routes {
			if r == route {
				result = append(result, ep)
				break
			}
		}
	}
	return result
}

// List returns status info for all endpoints.
func (m *Manager) List() []Info {
	m.mu.RLock()
	defer m.mu.RUnlock()

	infos := make([]Info, 0, len(m.endpoints))
	for _, ep := range m.endpoints {
		ep.mu.RLock()
		infos = append(infos, Info{
			Name:     ep.Config.Name,
			Address:  ep.Config.Address,
			State:    ep.State.String(),
			Priority: ep.Config.Priority,
			Routes:   ep.Config.Routes,
			LastSeen: ep.LastSeen,
		})
		ep.mu.RUnlock()
	}
	return infos
}

// Close shuts down all endpoint connections and stops health checkers.
func (m *Manager) Close() {
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ep := range m.endpoints {
		if ep.Conn != nil {
			_ = ep.Conn.Close()
		}
	}
}
