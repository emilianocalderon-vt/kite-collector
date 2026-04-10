# Streaming de kite-collector a OpenTelemetry (con archivo de config)

Este ejemplo levanta un OpenTelemetry Collector y ejecuta kite-collector
usando un archivo `kite.yaml` con el streaming habilitado.

## 1. Levantar el collector

```bash
docker compose up
```

El collector escucha en `localhost:4318` y muestra cada log record recibido
en stdout.

## 2. Ejecutar kite-collector

```bash
sudo ./bin/kite-collector agent --stream \
  --config examples/kite-otel/kite.yaml
```

> `sudo` es necesario en Linux para el inventario completo de software e interfaces.
> En Windows, ejecutar desde una terminal de Administrador.

kite-collector descubrirá el host local y enviará eventos de activos al
collector cada 60 segundos.

## 3. Verificar

En la terminal donde corre `docker compose up`, busca líneas con
`LogRecord` y `SeverityText`. Cada registro es un evento de activo.

Para confirmarlo de forma programática:

```bash
docker compose logs otel-collector 2>&1 | grep -c "LogRecord"
```

## Qué envía kite

Cada evento es un log record OTLP (`/v1/logs`) con los siguientes atributos:

| Atributo | Ejemplo |
|---|---|
| `service.name` | `kite-collector` |
| `event_type` | `AssetDiscovered`, `UnauthorizedAssetDetected`, `AssetNotSeen`, ... |
| `asset_id` | `019086a0-7c12-7de8-...` |
| `scan_run_id` | `019086a0-7c12-7de8-...` |
| `severity` | `low` / `medium` / `high` / `critical` |

## Próximos pasos

Reemplaza el exporter `debug` en `otel-collector.yaml` con cualquier backend:

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

Otros exporters comunes: `elasticsearch`, `file`, `otlphttp`, `datadog`, `splunk_hec`.
