# Streaming kite-collector to OpenTelemetry

This sample starts an OpenTelemetry Collector and shows how to point
kite-collector at it.

## 1. Start the collector

```bash
docker compose up
```

The collector listens on `localhost:4318` and prints every received log
record to stdout.

## 2. Run kite-collector

From the repo root (or wherever the binary lives), run a one-shot scan
with streaming enabled:

```bash
./kite-collector agent --stream --interval 1s \
  --config /dev/stdin <<'EOF'
streaming:
  otlp:
    endpoint: http://localhost:4318
    protocol: http
EOF
```

Or skip the config file and use environment variables:

```bash
KITE_STREAMING_OTLP_ENDPOINT=http://localhost:4318 \
KITE_STREAMING_OTLP_PROTOCOL=http \
  ./kite-collector agent --stream --interval 1s
```

After one scan cycle you will see OTLP log records in the collector
output with attributes like `event_type=AssetDiscovered`.

## 3. Verify

In the terminal running `docker compose up`, look for lines containing
`LogRecord` and `SeverityText`. Each record is one asset event.

To confirm programmatically:

```bash
docker compose logs otelcol 2>&1 | grep -c "LogRecord"
```

## What kite sends

Each event is an OTLP log record (`/v1/logs`) with:

| Attribute | Example |
|-----------|---------|
| `service.name` | `kite-collector` |
| `event_type` | `AssetDiscovered`, `UnauthorizedAssetDetected`, `AssetNotSeen`, ... |
| `asset_id` | `019086a0-7c12-7de8-...` |
| `scan_run_id` | `019086a0-7c12-7de8-...` |
| `severity` | `low` / `medium` / `high` / `critical` |

## Next steps

Replace the `debug` exporter in `otel-collector.yaml` with any backend:

```yaml
exporters:
  loki:
    endpoint: http://loki:3100/loki/api/v1/push

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [loki]
```

Other common exporters: `elasticsearch`, `file`, `otlphttp` (to forward
to another collector), `datadog`, `splunk_hec`.
