# Guia de Instalacion de Kite Collector en un Servidor

Esta guia cubre la instalacion y configuracion de **Kite Collector**, el agente de descubrimiento de activos de Vulnertrack Intelligence Engine, en un servidor Linux.

---

## Tabla de Contenidos

1. [Requisitos Previos](#1-requisitos-previos)
2. [Instalacion con Docker (recomendado)](#2-instalacion-con-docker-recomendado)
3. [Instalacion desde codigo fuente](#3-instalacion-desde-codigo-fuente)
4. [Configuracion](#4-configuracion)
5. [Ejecucion como servicio systemd](#5-ejecucion-como-servicio-systemd)
6. [Verificacion](#6-verificacion)
7. [Integracion con la plataforma](#7-integracion-con-la-plataforma)
8. [Resolucion de problemas](#8-resolucion-de-problemas)

---

## 1. Requisitos Previos

### Hardware minimo

| Recurso | Minimo | Recomendado |
|---------|--------|-------------|
| CPU     | 1 vCPU | 2 vCPU      |
| RAM     | 512 MB | 1 GB        |
| Disco   | 1 GB   | 5 GB        |

### Software necesario

- **Sistema operativo**: Ubuntu 22.04+, Debian 12+, RHEL 9+, o cualquier distribucion Linux moderna
- **Docker** (si se usa la instalacion con contenedores): Docker Engine 24+ y Docker Compose v2
- **Go 1.26+** (solo si se compila desde codigo fuente)
- **PostgreSQL 16** (requerido para el modo streaming)
- Acceso de red a los activos que se desean descubrir

### Puertos utilizados

| Puerto | Protocolo | Descripcion |
|--------|-----------|-------------|
| 9090   | TCP       | Metricas Prometheus |
| 8081   | TCP       | API HTTP (opcional) |
| 5432   | TCP       | PostgreSQL (si es local) |

---

## 2. Instalacion con Docker (recomendado)

Esta es la forma mas rapida de desplegar el agente.

### 2.1 Clonar el repositorio

```bash
git clone https://github.com/tu-org/vulnertack-intelligence-engine.git
cd vulnertack-intelligence-engine/apps/kite-collector
```

### 2.2 Crear el archivo de configuracion

```bash
cp configs/kite-collector.example.yaml configs/kite-collector.yaml
```

Editar `configs/kite-collector.yaml` segun las necesidades de tu red (ver [seccion 4](#4-configuracion)).

### 2.3 Configurar variables de entorno

Crear un archivo `.env` en el directorio `apps/kite-collector/`:

```bash
cat > .env << 'EOF'
KITE_POSTGRES_DSN=postgres://kite:kite@postgres:5432/kite?sslmode=disable
KITE_STREAMING_OTLP_ENDPOINT=otelcol:4318
KITE_STREAMING_OTLP_PROTOCOL=http
EOF
```

> **Importante**: Cambiar las credenciales por defecto (`kite:kite`) en entornos de produccion.

### 2.4 Levantar los servicios

```bash
docker compose up -d
```

Esto inicia dos contenedores:
- **kite-collector**: el agente de descubrimiento
- **postgres**: base de datos PostgreSQL para persistencia

### 2.5 Verificar que los contenedores estan corriendo

```bash
docker compose ps
docker compose logs -f kite-collector
```

---

## 3. Instalacion desde codigo fuente

### 3.1 Instalar Go

```bash
# Descargar e instalar Go 1.26
wget https://go.dev/dl/go1.26.1.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.26.1.linux-amd64.tar.gz

# Agregar al PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verificar
go version
```

### 3.2 Compilar el binario

```bash
cd vulnertack-intelligence-engine/apps/kite-collector
make build
```

El binario se genera en `bin/kite-collector`.

### 3.3 Instalar el binario

```bash
sudo cp bin/kite-collector /usr/local/bin/
sudo chmod +x /usr/local/bin/kite-collector

# Verificar
kite-collector --help
```

### 3.4 Crear directorios de configuracion

```bash
sudo mkdir -p /etc/kite
sudo mkdir -p /var/lib/kite/data

# Copiar la configuracion
sudo cp configs/kite-collector.example.yaml /etc/kite/config.yaml
```

### 3.5 Instalar PostgreSQL (si no existe)

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y postgresql-16

# Crear base de datos
sudo -u postgres psql -c "CREATE USER kite WITH PASSWORD 'CAMBIA_ESTA_CONTRASEÑA';"
sudo -u postgres psql -c "CREATE DATABASE kite OWNER kite;"
```

---

## 4. Configuracion

El archivo de configuracion principal es un YAML con las siguientes secciones:

### 4.1 Configuracion global

```yaml
log_level: info          # debug, info, warn, error
output_format: json      # json, table, csv
data_dir: /var/lib/kite/data  # ubicacion de la base SQLite
```

### 4.2 Fuentes de descubrimiento

Habilitar las fuentes segun la infraestructura disponible:

#### Escaneo de red

```yaml
discovery:
  sources:
    network:
      enabled: true
      scope:
        - 192.168.1.0/24      # redes a escanear
        - 10.0.0.0/16
      tcp_ports: [22, 80, 443, 3389, 8080, 8443]
      timeout: 5s
      max_concurrent: 256
```

#### Agente local (inventario del propio servidor)

```yaml
    agent:
      enabled: true
      collect_software: true     # inventario de software instalado
      collect_interfaces: true   # interfaces de red
```

#### Docker/Podman

```yaml
    docker:
      enabled: true
      host: unix:///var/run/docker.sock
```

#### Proveedores de nube (VPS)

Cada proveedor se activa individualmente. Las credenciales se pasan por variables de entorno:

```yaml
    hetzner:
      enabled: true
      # Requiere: KITE_HETZNER_TOKEN

    digitalocean:
      enabled: true
      # Requiere: KITE_DIGITALOCEAN_TOKEN

    vultr:
      enabled: true
      # Requiere: KITE_VULTR_TOKEN
```

Proveedores soportados: Hetzner, DigitalOcean, Vultr, Hostinger, Linode, Scaleway, OVHCloud, UpCloud, Kamatera.

#### Infraestructura on-premise

```yaml
    unifi:
      enabled: false
      endpoint: https://192.168.1.1:8443
      site: default
      # Requiere: KITE_UNIFI_USERNAME, KITE_UNIFI_PASSWORD

    proxmox:
      enabled: false
      endpoint: https://pve.local:8006
      # Requiere: KITE_PROXMOX_TOKEN_ID, KITE_PROXMOX_TOKEN_SECRET

    snmp:
      enabled: false
      community: public
      scope: [192.168.1.0/24]
```

#### MDM (gestion de dispositivos)

```yaml
    intune:
      enabled: false
      # Requiere: KITE_INTUNE_TENANT_ID, KITE_INTUNE_CLIENT_ID, KITE_INTUNE_CLIENT_SECRET

    jamf:
      enabled: false
      # Requiere: KITE_JAMF_API_URL, KITE_JAMF_USERNAME, KITE_JAMF_PASSWORD

    sccm:
      enabled: false
      # Requiere: KITE_SCCM_API_URL, KITE_SCCM_USERNAME, KITE_SCCM_PASSWORD
```

#### CMDB

```yaml
    netbox:
      enabled: false
      # Requiere: KITE_NETBOX_API_URL, KITE_NETBOX_TOKEN

    servicenow:
      enabled: false
      # Requiere: KITE_SERVICENOW_INSTANCE_URL, KITE_SERVICENOW_USERNAME, KITE_SERVICENOW_PASSWORD
```

### 4.3 Clasificacion de activos

```yaml
classification:
  authorization:
    allowlist_file: /etc/kite/authorized-assets.yaml
    match_fields: [hostname, mac_address]

  managed:
    required_controls: []   # vacio = opt-in
```

### 4.4 Deteccion de activos obsoletos

```yaml
stale_threshold: 168h       # 7 dias sin actividad = obsoleto
```

### 4.5 Metricas Prometheus

```yaml
metrics:
  enabled: true
  listen: :9090
```

---

## 5. Ejecucion como servicio systemd

Para que el agente se ejecute automaticamente al iniciar el servidor:

### 5.1 Crear el archivo de servicio

```bash
sudo cat > /etc/systemd/system/kite-collector.service << 'EOF'
[Unit]
Description=Kite Collector - Agente de descubrimiento de activos
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=kite
Group=kite
ExecStart=/usr/local/bin/kite-collector agent --stream --config /etc/kite/config.yaml
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Credenciales (ajustar segun las fuentes habilitadas)
Environment=KITE_POSTGRES_DSN=postgres://kite:CAMBIA_ESTA_CONTRASEÑA@localhost:5432/kite?sslmode=require
# Environment=KITE_HETZNER_TOKEN=tu-token-aqui
# Environment=KITE_DIGITALOCEAN_TOKEN=tu-token-aqui

# Seguridad
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/kite

[Install]
WantedBy=multi-user.target
EOF
```

### 5.2 Crear el usuario de servicio

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin kite
sudo chown -R kite:kite /var/lib/kite
sudo chown kite:kite /etc/kite/config.yaml
```

### 5.3 Habilitar e iniciar el servicio

```bash
sudo systemctl daemon-reload
sudo systemctl enable kite-collector
sudo systemctl start kite-collector
```

### 5.4 Verificar el estado

```bash
sudo systemctl status kite-collector
sudo journalctl -u kite-collector -f
```

---

## 6. Verificacion

### 6.1 Comprobar que el agente responde

```bash
# Metricas Prometheus
curl -s http://localhost:9090/metrics | head -20
```

### 6.2 Comprobar los logs

```bash
# Docker
docker compose logs -f kite-collector

# Systemd
journalctl -u kite-collector -f --no-pager
```

### 6.3 Ejecutar un escaneo manual

```bash
# Escaneo unico (sin modo streaming)
kite-collector agent --config /etc/kite/config.yaml
```

---

## 7. Integracion con la plataforma

### 7.1 Conexion con OpenTelemetry Collector

Para enviar los datos de descubrimiento a la plataforma central, configurar el endpoint OTLP:

```bash
# Variable de entorno
export KITE_STREAMING_OTLP_ENDPOINT=http://otelcol.vulnertrack.ejemplo.com:4318
export KITE_STREAMING_OTLP_PROTOCOL=http
```

O en el archivo de configuracion:

```yaml
streaming:
  interval: 6h
  otlp:
    endpoint: http://otelcol.vulnertrack.ejemplo.com:4318
    protocol: http
```

### 7.2 Conexion con PostgreSQL centralizado

Si la plataforma central expone una base PostgreSQL:

```bash
export KITE_POSTGRES_DSN=postgres://kite:contraseña@db.vulnertrack.ejemplo.com:5432/kite?sslmode=require
```

### 7.3 Despliegue completo con la plataforma

Para desplegar el agente junto con toda la plataforma Vulnertrack, usar el `docker-compose.yml` principal desde la raiz del repositorio:

```bash
cd vulnertack-intelligence-engine
docker compose up -d kite-collector kite-postgres redis clickhouse otelcol grafana
```

---

## 8. Resolucion de problemas

### El agente no puede escanear la red

- Verificar que el usuario tiene permisos para abrir sockets TCP
- Si se ejecuta en Docker, verificar que el contenedor tiene acceso a la red del host (`network_mode: host`) o que las redes objetivo son alcanzables
- Revisar las reglas de firewall (`iptables`, `ufw`, `firewalld`)

### Error de conexion a PostgreSQL

```bash
# Verificar conectividad
pg_isready -h localhost -p 5432 -U kite -d kite

# Verificar que la base de datos existe
psql -h localhost -U kite -d kite -c "SELECT 1;"
```

### El contenedor Docker no arranca

```bash
# Ver los logs de error
docker compose logs kite-collector

# Verificar que PostgreSQL esta listo
docker compose logs postgres
docker compose exec postgres pg_isready -U kite -d kite
```

### No se descubren contenedores Docker

- Verificar que el socket de Docker esta montado: `-v /var/run/docker.sock:/var/run/docker.sock`
- Verificar permisos: el usuario dentro del contenedor debe tener acceso al socket

### Las metricas no aparecen en Prometheus

- Verificar que el puerto 9090 esta abierto en el firewall
- Verificar la configuracion de `metrics.listen` en el YAML
- Probar acceso directo: `curl http://localhost:9090/metrics`

### Errores de TLS al conectar con proveedores cloud

- Verificar que los certificados CA del sistema estan actualizados:
  ```bash
  sudo apt update && sudo apt install -y ca-certificates
  ```
- Si se usa la imagen distroless, los certificados ya estan incluidos

### Reiniciar el agente limpiamente

```bash
# Docker
docker compose restart kite-collector

# Systemd
sudo systemctl restart kite-collector
```
