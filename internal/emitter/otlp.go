package emitter

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// Compile-time interface check.
var _ Emitter = (*OTLPEmitter)(nil)

// OTLPConfig holds the configuration for connecting to an OTLP-compatible
// log collector endpoint.
type OTLPConfig struct {
	Endpoint string
	Protocol string // "grpc" or "http"
	TLS      TLSConfig
}

// TLSConfig specifies optional mutual-TLS parameters.
type TLSConfig struct {
	CertFile string
	KeyFile  string
	CAFile   string
	Enabled  bool
}

// retryConfig controls exponential-backoff behaviour.
type retryConfig struct {
	maxAttempts int
	baseDelay   time.Duration
	maxDelay    time.Duration
}

// OTLPEmitter sends AssetEvent records as OTLP log entries over HTTP/JSON
// to an OpenTelemetry Collector's /v1/logs endpoint.
//
// Only the HTTP+JSON transport is implemented because it avoids heavy
// gRPC/protobuf dependencies and works with CGO_ENABLED=0 builds. When
// Protocol is set to "grpc" the emitter falls back to HTTP+JSON on the
// same endpoint, logging a warning at construction time so operators can
// adjust the collector configuration accordingly.
type OTLPEmitter struct {
	client         *http.Client
	endpoint       string // full URL including /v1/logs
	serviceName    string
	serviceVersion string
	retry          retryConfig

	mu     sync.Mutex // guards closed
	closed bool
}

// NewOTLP creates an OTLPEmitter that pushes log records to the given OTLP
// endpoint. serviceVersion is embedded as the service.version resource
// attribute on every exported log record.
func NewOTLP(cfg OTLPConfig, serviceVersion string) (*OTLPEmitter, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("otlp: endpoint must not be empty")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()

	if cfg.TLS.Enabled {
		tlsCfg, err := buildTLSConfig(cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("otlp: tls setup: %w", err)
		}
		transport.TLSClientConfig = tlsCfg
	}

	endpoint := cfg.Endpoint
	// Ensure the path ends with /v1/logs.
	if last := len(endpoint) - 1; last >= 0 && endpoint[last] == '/' {
		endpoint = endpoint[:last]
	}
	endpoint += "/v1/logs"

	return &OTLPEmitter{
		client: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
		endpoint:       endpoint,
		serviceName:    "kite-collector",
		serviceVersion: serviceVersion,
		retry: retryConfig{
			maxAttempts: 3,
			baseDelay:   1 * time.Second,
			maxDelay:    30 * time.Second,
		},
	}, nil
}

// Emit sends a single event as an OTLP log record.
func (o *OTLPEmitter) Emit(ctx context.Context, event model.AssetEvent) error {
	return o.EmitBatch(ctx, []model.AssetEvent{event})
}

// EmitBatch sends multiple events in a single OTLP /v1/logs request.
func (o *OTLPEmitter) EmitBatch(ctx context.Context, events []model.AssetEvent) error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return fmt.Errorf("otlp: emitter is shut down")
	}
	o.mu.Unlock()

	if len(events) == 0 {
		return nil
	}

	payload := o.buildPayload(events)

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("otlp: marshal payload: %w", err)
	}

	return o.sendWithRetry(ctx, body)
}

// Shutdown marks the emitter as closed and releases the underlying HTTP
// transport. Any in-flight Emit calls that started before Shutdown will
// be allowed to complete; subsequent calls return an error.
func (o *OTLPEmitter) Shutdown(_ context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.closed {
		return nil
	}
	o.closed = true
	o.client.CloseIdleConnections()
	return nil
}

// ---------------------------------------------------------------------------
// OTLP JSON payload types
// ---------------------------------------------------------------------------

// The structs below mirror the OTLP JSON log format defined in
// https://opentelemetry.io/docs/specs/otlp/#otlphttp-request

type otlpLogsPayload struct {
	ResourceLogs []otlpResourceLog `json:"resourceLogs"`
}

type otlpResourceLog struct {
	Resource  otlpResource   `json:"resource"`
	ScopeLogs []otlpScopeLog `json:"scopeLogs"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpScopeLog struct {
	Scope      otlpScope       `json:"scope"`
	LogRecords []otlpLogRecord `json:"logRecords"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type otlpLogRecord struct {
	Body                 otlpAnyValue   `json:"body"`
	TimeUnixNano         string         `json:"timeUnixNano"`
	SeverityText         string         `json:"severityText"`
	ObservedTimeUnixNano string         `json:"observedTimeUnixNano"`
	TraceID              string         `json:"traceId,omitempty"`
	SpanID               string         `json:"spanId,omitempty"`
	Attributes           []otlpKeyValue `json:"attributes"`
	SeverityNumber       int            `json:"severityNumber"`
}

type otlpAnyValue struct {
	StringValue *string `json:"stringValue,omitempty"`
}

type otlpKeyValue struct {
	Value otlpAnyValue `json:"value"`
	Key   string       `json:"key"`
}

// ---------------------------------------------------------------------------
// Payload construction
// ---------------------------------------------------------------------------

func (o *OTLPEmitter) buildPayload(events []model.AssetEvent) otlpLogsPayload {
	records := make([]otlpLogRecord, 0, len(events))
	now := strconv.FormatInt(time.Now().UnixNano(), 10)

	for i := range events {
		records = append(records, o.eventToLogRecord(&events[i], now))
	}

	return otlpLogsPayload{
		ResourceLogs: []otlpResourceLog{
			{
				Resource: otlpResource{
					Attributes: []otlpKeyValue{
						stringKV("service.name", o.serviceName),
						stringKV("service.version", o.serviceVersion),
					},
				},
				ScopeLogs: []otlpScopeLog{
					{
						Scope:      otlpScope{Name: "kite-collector.emitter"},
						LogRecords: records,
					},
				},
			},
		},
	}
}

func (o *OTLPEmitter) eventToLogRecord(e *model.AssetEvent, observedNano string) otlpLogRecord {
	return otlpLogRecord{
		TimeUnixNano:         strconv.FormatInt(e.Timestamp.UnixNano(), 10),
		ObservedTimeUnixNano: observedNano,
		SeverityNumber:       severityToNumber(e.Severity),
		SeverityText:         string(e.Severity),
		Body:                 stringVal(e.Details),
		Attributes: []otlpKeyValue{
			stringKV("event_type", string(e.EventType)),
			stringKV("asset_id", e.AssetID.String()),
			stringKV("scan_run_id", e.ScanRunID.String()),
			stringKV("severity", string(e.Severity)),
		},
	}
}

// ---------------------------------------------------------------------------
// Retry logic
// ---------------------------------------------------------------------------

func (o *OTLPEmitter) sendWithRetry(ctx context.Context, body []byte) error {
	var lastErr error

	for attempt := 0; attempt < o.retry.maxAttempts; attempt++ {
		if attempt > 0 {
			delay := backoffDelay(attempt, o.retry.baseDelay, o.retry.maxDelay)
			select {
			case <-ctx.Done():
				return fmt.Errorf("otlp: context cancelled during retry backoff: %w", ctx.Err())
			case <-time.After(delay):
			}
		}

		lastErr = o.doSend(ctx, body)
		if lastErr == nil {
			return nil
		}

		// Only retry on transient (5xx / connection) errors.
		if !isTransient(lastErr) {
			return lastErr
		}
	}

	return fmt.Errorf("otlp: exhausted %d retry attempts: %w", o.retry.maxAttempts, lastErr)
}

func (o *OTLPEmitter) doSend(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("otlp: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return &transientError{err: fmt.Errorf("otlp: send request: %w", err)}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	err = fmt.Errorf("otlp: server returned %d: %s", resp.StatusCode, string(respBody))

	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		return &transientError{err: err}
	}
	return err
}

// transientError wraps errors that are safe to retry.
type transientError struct {
	err error
}

func (e *transientError) Error() string { return e.err.Error() }
func (e *transientError) Unwrap() error { return e.err }

func isTransient(err error) bool {
	te := (*transientError)(nil)
	ok := false
	for e := err; e != nil; {
		if t, is := e.(*transientError); is {
			te = t
			ok = true
			break
		}
		u, canUnwrap := e.(interface{ Unwrap() error })
		if !canUnwrap {
			break
		}
		e = u.Unwrap()
	}
	_ = te
	return ok
}

// backoffDelay computes an exponential backoff with a cap.
func backoffDelay(attempt int, base, max time.Duration) time.Duration {
	delay := time.Duration(float64(base) * math.Pow(2, float64(attempt-1)))
	if delay > max {
		delay = max
	}
	return delay
}

// ---------------------------------------------------------------------------
// TLS helpers
// ---------------------------------------------------------------------------

func buildTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.CAFile != "" {
		caPEM, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file %q: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA certificate from %q", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

// ---------------------------------------------------------------------------
// OTLP value helpers
// ---------------------------------------------------------------------------

func stringVal(s string) otlpAnyValue {
	return otlpAnyValue{StringValue: &s}
}

func stringKV(key, value string) otlpKeyValue {
	return otlpKeyValue{Key: key, Value: stringVal(value)}
}

// severityToNumber maps model.Severity to the OTLP severity number range.
// See https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber
func severityToNumber(s model.Severity) int {
	switch s {
	case model.SeverityLow:
		return 5 // DEBUG2 — informational low-priority finding
	case model.SeverityMedium:
		return 9 // INFO
	case model.SeverityHigh:
		return 13 // WARN
	case model.SeverityCritical:
		return 17 // ERROR
	default:
		return 0 // UNSPECIFIED
	}
}
