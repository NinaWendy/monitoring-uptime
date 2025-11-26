# Uptime Kuma Webhook → Fluent Bit → Wazuh

A production‑grade Go webhook service that receives Uptime Kuma notifications, writes structured JSON logs to disk, and ships them with Fluent Bit to Wazuh (or any downstream system that accepts JSON/log streams).

## Features

- Accepts Uptime Kuma webhook notifications (DNS, ping, HTTP, etc.).[1][2]
- Normalizes events into a consistent JSON log format.
- Buffered, batched, and rotated file logging under `/srv/uptime-kuma`.
- Rate limiting, request size limits, and graceful shutdown for production use.[3][4]
- Health (`/health`) and Prometheus‑style metrics (`/metrics`) endpoints.
- Fluent Bit tail input, JSON parsing, and output to Wazuh.
- Runs as a hardened systemd service under a dedicated user.

## Architecture

High‑level flow:

- Uptime Kuma monitor → Webhook HTTP POST → Go service `/webhook`
- Go service → JSON log line → `/srv/uptime-kuma/webhook.log`
- Fluent Bit `tail` input → parse JSON → forward to Wazuh (HTTP or TCP)

You can add an architecture diagram here.

## Requirements

- Linux (systemd based, e.g. Ubuntu)
- Go 1.21+ (for building)
- Fluent Bit installed (e.g. from official packages)
- Wazuh manager (or any log receiver supported by Fluent Bit)
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

Fields may vary slightly depending on the monitor type and Uptime Kuma payload.[5]

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/NinaWendy/monitoring-uptime
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

## Fluent Bit integration

This section configures Fluent Bit to tail the webhook log and forward it to Wazuh. Adjust paths and output as required by your environment.

### 1. Base Fluent Bit configuration

On many systems, the main config is `/etc/fluent-bit/fluent-bit.conf`. A simple structure:

```ini
[SERVICE]
    Flush        1
    Daemon       Off
    Log_Level    info

    # Optional: HTTP server for Fluent Bit metrics
    # HTTP_Server On
    # HTTP_Listen 0.0.0.0
    # HTTP_Port   2020

@INCLUDE inputs.d/*.conf
@INCLUDE filters.d/*.conf
@INCLUDE outputs.d/*.conf
```

Create the `inputs.d`, `filters.d`, and `outputs.d` directories if they do not exist.

```bash
sudo mkdir -p /etc/fluent-bit/inputs.d /etc/fluent-bit/filters.d /etc/fluent-bit/outputs.d
```

### 2. Tail input for Uptime Kuma logs

Create `/etc/fluent-bit/inputs.d/uptime-kuma.conf`:

```ini
[INPUT]
    Name              tail
    Path              /srv/uptime-kuma/webhook.log
    Tag               uptime_kuma
    Parser            json
    Mem_Buf_Limit     10MB
    Skip_Long_Lines   On
    Refresh_Interval  5
    Rotate_Wait       5
    DB                /var/lib/fluent-bit/uptime-kuma.db
    DB.Sync           Normal
```

This tells Fluent Bit to:

- Follow `/srv/uptime-kuma/webhook.log`.
- Treat each line as JSON.
- Keep state in a SQLite DB so it resumes correctly across restarts.[6]

### 3. JSON parser (if needed)

If Fluent Bit doesn’t already have a suitable JSON parser enabled, add one in `/etc/fluent-bit/parsers.conf`:

```ini
[PARSER]
    Name        json
    Format      json
    Time_Key    timestamp
    Time_Format %Y-%m-%dT%H:%M:%S
    Time_Keep   On
```

And include it in `fluent-bit.conf`:

```ini
@INCLUDE parsers.conf
```

Adjust `Time_Key` and `Time_Format` if you want Fluent Bit to use your `timestamp` field as the event time; otherwise, you can omit the time directives and let Fluent Bit assign its own time.

### 4. Optional filters

You can add filters to rename fields, add metadata, or drop noise. Example `/etc/fluent-bit/filters.d/uptime-kuma.conf`:

```ini
[FILTER]
    Name          modify
    Match         uptime_kuma
    Add           source uptime-kuma-webhook

# Example: only keep DOWN events
# [FILTER]
#     Name      grep
#     Match     uptime_kuma
#     Regex     status   DOWN
```

### 5. Output to Wazuh

There are multiple ways to send logs to Wazuh from Fluent Bit. The simplest is to use an output plugin compatible with Wazuh’s ingestion, such as syslog or HTTP, depending on your Wazuh setup.

Example: send JSON over TCP to a syslog receiver on the Wazuh manager:

```ini
[OUTPUT]
    Name            syslog
    Match           uptime_kuma
    Host            <WAZUH_MANAGER_IP>
    Port            514
    Mode            tcp
    Syslog_Format   rfc5424
    Syslog_Hostname ${HOSTNAME}
    Syslog_Appname  uptime-kuma
    Syslog_Procid   -
    Syslog_Message_Key log
```

If your Fluent Bit version doesn’t support the `syslog` output, you can instead use:

- `forward` output to a Fluentd/Fluent Bit aggregator.
- `http` output if you have an HTTP input on the Wazuh side.
- `tcp` output to a custom receiver you control.

Consult Wazuh’s Fluent Bit integration docs for the officially recommended output format and plugin for your version.[7]

Restart Fluent Bit after configuration changes:

```bash
sudo systemctl restart fluent-bit
sudo systemctl status fluent-bit
```

## Uptime Kuma configuration

In Uptime Kuma:

1. Go to Settings → Notifications.[2][1]
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
       "msg": "{{msg}}"
     }
     ```
4. Attach this notification to the monitors (DNS, ping, HTTP, etc.) you want to send through this pipeline.
5. Trigger an actual state change (e.g. bring a monitored endpoint down) and verify:
   - `/srv/uptime-kuma/webhook.log` is populated with JSON.
   - Fluent Bit shows tail activity for the `uptime_kuma` tag.
   - Wazuh receives and indexes the events.

## Endpoints

- `POST /webhook`  
  Receives Uptime Kuma alerts in JSON.

- `GET /health`  
  Returns a small JSON indicating service health and basic stats.

- `GET /metrics`  
  Exposes Prometheus‑style metrics for monitoring the service.

## Configuration (Environment Variables)

Key environment variables:

- `WEBHOOK_PORT` – Port for webhook and health (default: 8080).
- `METRICS_PORT` – Port for metrics (default: 9090).
- `LOG_FILE` – Path to the log file (default: `/srv/uptime-kuma/webhook.log`).
- `LOG_DIR` – Directory for logs (default: `/srv/uptime-kuma`).
- `MAX_LOG_SIZE` – Max log file size in bytes before rotation.
- `BUFFER_SIZE` – In‑memory log buffer size.
- `FLUSH_INTERVAL` – Batch flush interval (e.g. `1s`).
- `RATE_LIMIT_PER_SECOND`, `RATE_LIMIT_BURST` – Request rate limiting.
- `MAX_REQUEST_BODY_SIZE` – Maximum accepted request body size.
- `ENABLE_METRICS` – Enable/disable `/metrics` endpoint.

## Security Notes

- Intended to run under a non‑root `webhook` user.
- Systemd sandboxing and limited writable paths reduce risk in case of compromise.
- Use firewall rules to restrict access to ports 8080 (webhook) and metrics.
- Fluent Bit should run with least privileges needed to read `/srv/uptime-kuma/webhook.log` and reach the Wazuh endpoint.