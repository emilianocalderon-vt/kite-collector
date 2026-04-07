# Windows Quickstart

This guide walks you through installing and running kite-collector on Windows.

## Install

### Option 1: PowerShell one-liner (recommended)

Open PowerShell and run:

```powershell
irm https://get.kite-collector.dev/install.ps1 | iex
```

This downloads the latest binary to `%LOCALAPPDATA%\kite-collector\` and adds it to your user PATH.

### Option 2: Manual download

1. Go to [GitHub Releases](https://github.com/VulnerTrack/kite-collector/releases)
2. Download `kite-collector_windows_amd64.exe`
3. Move it to a folder in your PATH, or run it from the download location

### Option 3: Double-click

Download `kite-collector_windows_amd64.exe`, rename it to `kite-collector.exe`, and double-click it. An interactive menu will appear.

## First scan

Open a command prompt or PowerShell and run:

```
kite-collector scan
```

This scans the local machine and stores results in `.\data\kite.db`.

## Interactive setup

Run the setup wizard to detect available services and configure credentials:

```
kite-collector init
```

The wizard will:
1. Scan for infrastructure services (Docker, Wazuh, etc.)
2. Prompt for credentials when needed
3. Generate a `kite-collector.yaml` config file
4. Show `set` (CMD) or `$env:` (PowerShell) commands for environment variables

## Docker on Windows

kite-collector automatically detects Docker Desktop via:
1. The Windows named pipe `\\.\pipe\docker_engine`
2. TCP fallback on `localhost:2375`

If Docker Desktop is running, it will be detected by `kite-collector scan --auto` or `kite-collector init`.

### Enabling TCP access

If named pipe access fails, enable TCP in Docker Desktop:
1. Open Docker Desktop Settings
2. Go to General
3. Check "Expose daemon on tcp://localhost:2375 without TLS"

## Environment variables

On Windows CMD:
```cmd
set KITE_WAZUH_USERNAME=admin
set KITE_WAZUH_PASSWORD=secret
kite-collector scan --auto
```

On Windows PowerShell:
```powershell
$env:KITE_WAZUH_USERNAME="admin"
$env:KITE_WAZUH_PASSWORD="secret"
kite-collector scan --auto
```

kite-collector automatically detects CMD vs PowerShell and shows the correct syntax in its output.

## Query results

```
kite-collector query assets
kite-collector query software --limit 20
kite-collector query findings
kite-collector query scans
```

## Dashboard

Open the browser dashboard:

```
kite-collector dashboard
```

This starts a local web server on `http://localhost:9876` and opens your browser. The dashboard works fully offline -- all assets are embedded in the binary.

## Error lookup

If you encounter an error code, look it up:

```
kite-collector error KITE-E001
```

This shows the error message, cause, and Windows-specific remediation steps.

## Troubleshooting

### "kite-collector is not recognized"

The binary is not in your PATH. Either:
- Run the PowerShell installer (adds to PATH automatically)
- Add the directory containing `kite-collector.exe` to your PATH manually
- Use the full path: `C:\path\to\kite-collector.exe scan`

### "Docker not accessible" (KITE-E001)

1. Ensure Docker Desktop is running
2. Check Settings > General > "Expose daemon on tcp://localhost:2375"
3. Run: `kite-collector error KITE-E001` for detailed instructions

### "Permission denied" (KITE-E008)

Run the command prompt or PowerShell as Administrator:
- Right-click > "Run as Administrator"
- Or run from an elevated prompt
