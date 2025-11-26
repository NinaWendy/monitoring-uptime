# Uptime Kuma Webhook

A production‑grade Go webhook service that receives Uptime Kuma notifications, writes structured JSON logs to disk, and forwards them via rsyslog to Wazuh for centralized monitoring and alerting.

┌─────────────────────────────────────────────────────────────────┐
│                    Uptime Kuma Instances                        │
│         (Multiple monitors: DNS, Ping, HTTP, etc.)              │
└────────────────┬────────────────────────────────────────────────┘
                 │ HTTP Webhooks (with retry)
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│              Load Balancer (HAProxy/Nginx) [Optional]           │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│          Go Webhook Service (Multiple Instances)                │
│  • Connection pooling    • Rate limiting                        │
│  • Buffering            • Circuit breaker                       │
│  • Metrics/Monitoring   • Health checks                         │
└────────────────┬────────────────────────────────────────────────┘
                 │ Write to buffer
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│               Buffered File Writer (Async)                      │
│  • Batch writes         • Compression                           │
│  • Ring buffer          • Size-based rotation                   │
└────────────────┬────────────────────────────────────────────────┘
                 │ Append to file
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│         /srv/uptime-kuma/webhook.log                            │
│         (Optimized rsyslog monitoring)                          │
└────────────────┬────────────────────────────────────────────────┘
                 │ Read via imfile (with state)
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│           Rsyslog (High-Performance Config)                     │
│  • Batch processing     • Queue management                      │
│  • Compression          • Rate limiting                         │
└────────────────┬────────────────────────────────────────────────┘
                 │ Forward (TCP with compression)
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│              Wazuh Manager (Centralized SIEM)                   │
│  • Custom decoders      • Alerting rules                        │
│  • Analytics            • Dashboards                            │
└─────────────────────────────────────────────────────────────────┘

## Features

- Accepts Uptime Kuma webhook notifications (DNS, ping, HTTP, etc.).
- Normalizes events into a consistent JSON log format.
- Buffered, batched, and rotated file logging under `/srv/uptime-kuma`.
- Rate limiting, request size limits, and graceful shutdown.
- Health (`/health`) and Prometheus‑style metrics (`/metrics`) endpoints.
- Rsyslog integration (imfile) for forwarding logs to Wazuh.
- Runs as a hardened systemd service under a dedicated user.

## Architecture

High‑level flow:

- Uptime Kuma monitor → Webhook HTTP POST → Go service `/webhook`
- Go service → JSON log line → `/srv/uptime-kuma/webhook.log`
- rsyslog imfile → reads JSON lines → forwards to Wazuh (TCP)

You can add an architecture diagram here.

## Requirements

- Linux (systemd‑based, e.g. Ubuntu)
- Go 1.21+ (for building)
- rsyslog with `imfile` module
- Wazuh manager (or any syslog‑compatible receiver)
- Uptime Kuma instance configured to send webhooks

## Log Format

Each event is written as a single JSON line to `/srv/uptime-kuma/webhook.log`, for example:

```json
{
  "timestamp": "2025-11-24T10:12:52.969144398+03:00",
  "monitor_id": 12,
  "monitor_name": "dns-node-a-to-node-b",
  "monitor_type": "dns",
  "target_host": "node-b.example.internal",
  "target_url": "",
  "status": "DOWN",
  "message": "DNS lookup failed",
  "ping_ms": 0,
  "duration_seconds": 60,
  "uptime_count": 120,
  "downtime_count": 3,
  "dns_resolve_type": "A",
  "dns_resolve_server": "8.8.8.8",
  "port": 53,
  "check_interval_seconds": 60
}
```

Fields may vary slightly depending on the monitor type and Uptime Kuma payload.

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/NinaWendy/monitoring-uptime.git
cd webhook
```

### 2. Build the binary

```bash
go build -o uptime-kuma-webhook main.go
```

### 3. Create runtime directories and user

```bash
sudo useradd -r -s /bin/false webhook || true
sudo mkdir -p /opt/uptime-kuma-webhook
sudo mkdir -p /srv/uptime-kuma
sudo chown webhook:webhook /opt/uptime-kuma-webhook /srv/uptime-kuma
sudo chmod 755 /srv/uptime-kuma
```

Copy the binary:

```bash
sudo cp uptime-kuma-webhook /opt/uptime-kuma-webhook/
sudo chown webhook:webhook /opt/uptime-kuma-webhook/uptime-kuma-webhook
```

### 4. Systemd service

Create `/etc/systemd/system/uptime-kuma-webhook.service`:

```ini
[Unit]
Description=Uptime Kuma Webhook Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=webhook
Group=webhook
WorkingDirectory=/opt/uptime-kuma-webhook

Environment="WEBHOOK_PORT=8080"
Environment="METRICS_PORT=9090"
Environment="LOG_FILE=/srv/uptime-kuma/webhook.log"
Environment="LOG_DIR=/srv/uptime-kuma"
Environment="MAX_LOG_SIZE=104857600"
Environment="BUFFER_SIZE=10000"
Environment="FLUSH_INTERVAL=1s"
Environment="MAX_CONCURRENT_WRITES=4"
Environment="RATE_LIMIT_PER_SECOND=10000"
Environment="RATE_LIMIT_BURST=20000"
Environment="READ_TIMEOUT=5s"
Environment="WRITE_TIMEOUT=10s"
Environment="IDLE_TIMEOUT=120s"
Environment="SHUTDOWN_TIMEOUT=30s"
Environment="MAX_REQUEST_BODY_SIZE=1048576"
Environment="ENABLE_METRICS=true"

ExecStart=/opt/uptime-kuma-webhook/uptime-kuma-webhook

Restart=always
RestartSec=5

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/srv/uptime-kuma
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
```

Reload and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now uptime-kuma-webhook
sudo systemctl status uptime-kuma-webhook
```

### 5. Rsyslog integration

Create `/etc/rsyslog.d/app.conf`:

```conf
$ModLoad imfile
$InputFilePollInterval 5

$InputFileName /srv/uptime-kuma/webhook.log
$InputFileTag UptimeKuma:
$InputFileSeverity info
$InputFileFacility local7
$InputFileStateFile stat-uptime-kuma
$InputFilePersistStateInterval 100

$InputRunFileMonitor
```

Create or edit `/etc/rsyslog.d/default.conf` (or `50-default.conf`):

```conf
# Forward Uptime Kuma webhook logs (facility local7) to Wazuh
local7.*                        @@<WAZUH_MANAGER_IP>:<PORT>

auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          -/var/log/syslog
kern.*                          -/var/log/kern.log
mail.*                          -/var/log/mail.log
mail.err                        /var/log/mail.err
*.emerg                         :omusrmsg:*
```

Restart rsyslog:

```bash
sudo systemctl restart rsyslog
```

### 6. Uptime Kuma configuration

In Uptime Kuma:

1. Go to Settings → Notifications.
2. Add a new notification of type “Webhook”.
3. Configure:
   - URL: `http://<webhook_server_ip>:8080/webhook`
   - Method: `POST`
   - Content Type: `application/json`
   - Body:
     ```json
     {
       "heartbeat": {{heartbeatJSON}},
       "monitor": {{monitorJSON}},
       "msg": "{{msg}}
     }
     ```
4. Attach this notification to the monitors (DNS, ping, etc.) you want to send to Wazuh.
5. Trigger an actual state change (e.g. bring a monitored endpoint down) and verify that:
   - `/srv/uptime-kuma/webhook.log` is populated.
   - Wazuh receives and parses the events.

## Endpoints

- `POST /webhook`  
  Receives Uptime Kuma alerts in JSON.

- `GET /health`  
  Returns a small JSON indicating service health and basic stats.

- `GET /metrics`  
  Exposes Prometheus‑style metrics for monitoring the service.

## Configuration (Environment Variables)

Key environment variables:

- `WEBHOOK_PORT` – HTTP port for the webhook and health endpoints (default: 8080).
- `METRICS_PORT` – HTTP port for metrics (default: 9090).
- `LOG_FILE` – Path to the log file (default: `/srv/uptime-kuma/webhook.log`).
- `LOG_DIR` – Directory for logs (default: `/srv/uptime-kuma`).
- `MAX_LOG_SIZE` – Max log file size in bytes before rotation.
- `BUFFER_SIZE` – Size of the in‑memory log buffer.
- `FLUSH_INTERVAL` – Batch flush interval (e.g. `1s`).
- `RATE_LIMIT_PER_SECOND`, `RATE_LIMIT_BURST` – Request rate limiting.
- `MAX_REQUEST_BODY_SIZE` – Maximum accepted request body size.

## Development

- Install Go 1.21+.
- Clone the repo and run:

```bash
go test ./...
go run main.go
```

By default this will listen on `:8080` and write logs under `/srv/uptime-kuma` (ensure the directory exists and is writable in your dev environment, or override `LOG_DIR`/`LOG_FILE`).

## Security Notes

- The service is intended to run under a non‑root user.
- Systemd sandboxing is strongly recommended (see the unit file example).
- Restrict access to ports 8080 and metrics using firewall rules as appropriate.
- Validate Wazuh and rsyslog configuration in a non‑production environment before rolling out widely.