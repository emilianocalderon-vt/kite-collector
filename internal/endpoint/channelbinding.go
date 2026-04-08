package endpoint

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

const channelBindingHeader = "x-channel-binding"

// TLSStateCapture wraps TransportCredentials to cache the TLS connection
// state after handshake. Interceptors use the cached state to compute
// RFC 9266 channel bindings without requiring per-RPC state extraction.
type TLSStateCapture struct {
	inner  credentials.TransportCredentials
	states map[string]tls.ConnectionState
	mu     sync.RWMutex
}

// NewTLSStateCapture wraps the given TransportCredentials so that the
// TLS connection state is captured after each successful handshake.
func NewTLSStateCapture(creds credentials.TransportCredentials) *TLSStateCapture {
	return &TLSStateCapture{
		inner:  creds,
		states: make(map[string]tls.ConnectionState),
	}
}

// ClientHandshake delegates to the inner credentials and caches the
// resulting TLS state.
func (c *TLSStateCapture) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, auth, err := c.inner.ClientHandshake(ctx, authority, rawConn)
	if err != nil {
		return conn, auth, err
	}
	if info, ok := auth.(credentials.TLSInfo); ok {
		c.mu.Lock()
		c.states[authority] = info.State
		c.mu.Unlock()
	}
	return conn, auth, nil
}

// ServerHandshake delegates to the inner credentials.
func (c *TLSStateCapture) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c.inner.ServerHandshake(conn)
}

// Info delegates to the inner credentials.
func (c *TLSStateCapture) Info() credentials.ProtocolInfo {
	return c.inner.Info()
}

// Clone returns a new TLSStateCapture wrapping a clone of the inner
// credentials. The state cache starts empty.
func (c *TLSStateCapture) Clone() credentials.TransportCredentials {
	return NewTLSStateCapture(c.inner.Clone())
}

// OverrideServerName delegates to the inner credentials.
//
//nolint:staticcheck // OverrideServerName is deprecated but required by the interface.
func (c *TLSStateCapture) OverrideServerName(name string) error {
	return c.inner.OverrideServerName(name) //nolint:staticcheck
}

// GetState returns the cached TLS connection state for the given
// authority (host:port). Returns false if no state has been captured yet
// (e.g. before the first RPC triggers the TLS handshake).
func (c *TLSStateCapture) GetState(authority string) (tls.ConnectionState, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	state, ok := c.states[authority]
	return state, ok
}

// ChannelBindingInterceptor returns a gRPC unary client interceptor that
// embeds a tls-exporter channel binding value (RFC 9266) in request
// metadata. The server can compare its own binding to detect TLS-
// terminating proxies. If capture is nil, the interceptor is a no-op.
func ChannelBindingInterceptor(capture *TLSStateCapture) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		if capture != nil {
			binding := computeBinding(capture, cc)
			if binding != "" {
				ctx = metadata.AppendToOutgoingContext(ctx, channelBindingHeader, binding)
			}
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// ChannelBindingStreamInterceptor returns a gRPC stream client interceptor
// that embeds the tls-exporter channel binding in stream metadata.
// If capture is nil, the interceptor is a no-op.
func ChannelBindingStreamInterceptor(capture *TLSStateCapture) grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		if capture != nil {
			binding := computeBinding(capture, cc)
			if binding != "" {
				ctx = metadata.AppendToOutgoingContext(ctx, channelBindingHeader, binding)
			}
		}
		return streamer(ctx, desc, cc, method, opts...)
	}
}

func computeBinding(capture *TLSStateCapture, cc *grpc.ClientConn) string {
	state, ok := capture.GetState(cc.Target())
	if !ok {
		return ""
	}
	binding, err := state.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(binding)
}

// VerifyChannelBinding is a server-side helper that extracts the
// channel binding from incoming metadata and compares it against the
// server's TLS state. Returns nil if binding matches or is absent.
func VerifyChannelBinding(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil // no metadata — skip check
	}

	bindings := md.Get(channelBindingHeader)
	if len(bindings) == 0 {
		return nil // no binding sent — skip check
	}

	// Server-side TLS state is available from the transport credentials.
	reqInfo, reqOK := credentials.RequestInfoFromContext(ctx)
	if !reqOK || reqInfo.AuthInfo == nil {
		return nil // no auth info
	}
	authInfo, authOK := reqInfo.AuthInfo.(credentials.TLSInfo)
	if !authOK {
		return nil // not a TLS connection
	}

	serverBinding, err := authInfo.State.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
	if err != nil {
		return fmt.Errorf("server channel binding export: %w", err)
	}

	expected := base64.StdEncoding.EncodeToString(serverBinding)
	if bindings[0] != expected {
		return fmt.Errorf("channel binding mismatch: client and server TLS sessions differ (possible TLS-terminating proxy)")
	}

	return nil
}
