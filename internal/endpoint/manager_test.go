package endpoint

import (
	"context"
	"crypto/tls"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/vulnertrack/kite-collector/internal/config"
)

func TestBackoff(t *testing.T) {
	d0 := backoff(0)
	assert.GreaterOrEqual(t, d0, 700*time.Millisecond)
	assert.LessOrEqual(t, d0, 1300*time.Millisecond)

	d5 := backoff(5)
	assert.GreaterOrEqual(t, d5, 22*time.Second)
	assert.LessOrEqual(t, d5, 42*time.Second)

	// High attempt should be capped.
	d100 := backoff(100)
	assert.LessOrEqual(t, d100, backoffMax+time.Duration(float64(backoffMax)*backoffJitter))
}

func TestEndpointStateTransitions(t *testing.T) {
	m := &Manager{logger: slog.Default()}
	ep := &Endpoint{
		Config: config.EndpointConfig{Name: "test"},
		State:  StateHealthy,
	}

	// 3 failures → degraded.
	for i := 0; i < failuresToDegrade; i++ {
		m.recordFailure(ep)
	}
	assert.Equal(t, StateDegraded, ep.State)

	// 3 more failures → unreachable.
	for i := 0; i < failuresToUnreachable; i++ {
		m.recordFailure(ep)
	}
	assert.Equal(t, StateUnreachable, ep.State)

	// 1 success → degraded.
	m.recordSuccess(ep)
	assert.Equal(t, StateDegraded, ep.State)

	// 3 successes → healthy.
	m.recordSuccess(ep) // already counted 1
	m.recordSuccess(ep)
	m.recordSuccess(ep)
	assert.Equal(t, StateHealthy, ep.State)
}

func TestForRoute_ReturnsHighestPriority(t *testing.T) {
	m := &Manager{
		logger: slog.Default(),
		endpoints: []*Endpoint{
			{
				Config: config.EndpointConfig{
					Name:     "secondary",
					Priority: 2,
					Routes:   []string{"assets", "heartbeat"},
				},
				State: StateHealthy,
			},
			{
				Config: config.EndpointConfig{
					Name:     "primary",
					Priority: 1,
					Routes:   []string{"assets", "heartbeat", "findings"},
				},
				State: StateHealthy,
			},
		},
	}
	// Sort by priority as NewManager would.
	m.endpoints[0], m.endpoints[1] = m.endpoints[1], m.endpoints[0]

	ep := m.ForRoute("assets")
	require.NotNil(t, ep)
	assert.Equal(t, "primary", ep.Config.Name)
}

func TestForRoute_FailoverToSecondary(t *testing.T) {
	m := &Manager{
		logger: slog.Default(),
		endpoints: []*Endpoint{
			{
				Config: config.EndpointConfig{
					Name:     "primary",
					Priority: 1,
					Routes:   []string{"assets"},
				},
				State: StateUnreachable,
			},
			{
				Config: config.EndpointConfig{
					Name:     "secondary",
					Priority: 2,
					Routes:   []string{"assets"},
				},
				State: StateHealthy,
			},
		},
	}

	ep := m.ForRoute("assets")
	require.NotNil(t, ep)
	assert.Equal(t, "secondary", ep.Config.Name)
}

func TestForRoute_NoHealthyEndpoint(t *testing.T) {
	m := &Manager{
		logger: slog.Default(),
		endpoints: []*Endpoint{
			{
				Config: config.EndpointConfig{
					Name:   "primary",
					Routes: []string{"assets"},
				},
				State: StateUnreachable,
			},
		},
	}

	ep := m.ForRoute("assets")
	assert.Nil(t, ep)
}

func TestList(t *testing.T) {
	now := time.Now()
	m := &Manager{
		logger: slog.Default(),
		endpoints: []*Endpoint{
			{
				Config: config.EndpointConfig{
					Name:     "ep1",
					Address:  "a:443",
					Priority: 1,
					Routes:   []string{"assets"},
				},
				State:    StateHealthy,
				LastSeen: now,
			},
		},
	}

	infos := m.List()
	require.Len(t, infos, 1)
	assert.Equal(t, "ep1", infos[0].Name)
	assert.Equal(t, "healthy", infos[0].State)
}

func TestTLSStateCapture_StoreAndRetrieve(t *testing.T) {
	// TLSStateCapture should store and return state by authority.
	capture := NewTLSStateCapture(nil)

	_, ok := capture.GetState("example.com:443")
	assert.False(t, ok, "no state should exist before handshake")

	// Simulate a captured TLS state.
	capture.mu.Lock()
	capture.states["example.com:443"] = tls.ConnectionState{
		Version:            tls.VersionTLS13,
		ServerName:         "example.com",
		HandshakeComplete:  true,
		NegotiatedProtocol: "h2",
	}
	capture.mu.Unlock()

	state, ok := capture.GetState("example.com:443")
	require.True(t, ok)
	assert.Equal(t, uint16(tls.VersionTLS13), state.Version)
	assert.Equal(t, "example.com", state.ServerName)
	assert.True(t, state.HandshakeComplete)

	// Different authority returns nothing.
	_, ok = capture.GetState("other.com:443")
	assert.False(t, ok)
}

func TestChannelBindingInterceptor_NilCapture(t *testing.T) {
	// With nil capture, the interceptor should be a transparent pass-through.
	interceptor := ChannelBindingInterceptor(nil)
	called := false
	invoker := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		called = true
		return nil
	}
	err := interceptor(context.Background(), "/test", nil, nil, nil, invoker)
	require.NoError(t, err)
	assert.True(t, called)
}

func TestQueue(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	q, err := NewQueue(ctx, dir, slog.Default())
	require.NoError(t, err)
	defer func() { _ = q.Close() }()

	// Initially empty.
	depth, err := q.Depth(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, depth)

	// Enqueue.
	require.NoError(t, q.Enqueue(ctx, "assets", []byte("payload1")))
	require.NoError(t, q.Enqueue(ctx, "assets", []byte("payload2")))
	require.NoError(t, q.Enqueue(ctx, "heartbeat", []byte("hb1")))

	depth, err = q.Depth(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, depth)

	// Peek assets.
	items, err := q.Peek(ctx, "assets", 10)
	require.NoError(t, err)
	assert.Len(t, items, 2)

	// Remove first.
	require.NoError(t, q.Remove(ctx, items[0].ID))
	depth, err = q.Depth(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, depth)
}
