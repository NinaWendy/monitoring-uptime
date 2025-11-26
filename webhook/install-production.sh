#!/bin/bash
# Production installation script

set -euo pipefail

echo "========================================="
echo " Uptime Kuma Webhook - Production Setup"
echo "========================================="
echo

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Get Wazuh manager IP
read -p "Enter Wazuh Manager IP address: " WAZUH_IP
if [ -z "$WAZUH_IP" ]; then
    echo "Error: Wazuh IP is required"
    exit 1
fi

# Create user
echo "Creating webhook user..."
if ! id "webhook" &>/dev/null; then
    useradd -r -s /bin/false webhook
fi

# Create directories
echo "Creating directories..."
mkdir -p /opt/uptime-kuma-webhook
mkdir -p /srv/uptime-kuma
mkdir -p /var/spool/rsyslog

# Set permissions
chown webhook:webhook /srv/uptime-kuma
chmod 755 /srv/uptime-kuma

# Build Go binary
echo "Building webhook service..."
go get golang.org/x/time/rate
CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-X 'main.Version=1.0.0' -X 'main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)' -X 'main.GitCommit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)'" \
    -o /opt/uptime-kuma-webhook/uptime-kuma-webhook \
    main.go

# Set binary permissions
chown webhook:webhook /opt/uptime-kuma-webhook/uptime-kuma-webhook
chmod 755 /opt/uptime-kuma-webhook/uptime-kuma-webhook

# Install systemd service
echo "Installing systemd service..."
cp uptime-kuma-webhook.service /etc/systemd/system/
systemctl daemon-reload

# Configure rsyslog
echo "Configuring rsyslog..."
cp rsyslog-uptime-kuma.conf /etc/rsyslog.d/uptime-kuma.conf
sed -i "s/YOUR_WAZUH_MANAGER_IP/$WAZUH_IP/g" /etc/rsyslog.d/uptime-kuma.conf

# Increase rsyslog limits
if ! grep -q "uptime-kuma" /etc/security/limits.conf; then
    echo "rsyslog soft nofile 65536" >> /etc/security/limits.conf
    echo "rsyslog hard nofile 65536" >> /etc/security/limits.conf
fi

# Restart rsyslog
echo "Restarting rsyslog..."
systemctl restart rsyslog

# Enable and start webhook service
echo "Starting webhook service..."
systemctl enable uptime-kuma-webhook.service
systemctl start uptime-kuma-webhook.service

# Wait for service to start
sleep 3

# Get the server IP and print out instructions
SERVER_IP=$(hostname -I | awk '{print $1}')
echo
echo "========================================="
echo " Installation Complete!"
echo "========================================="
echo
systemctl status uptime-kuma-webhook.service --no-pager
echo
echo "Service endpoints:"
echo "  Webhook: http://${SERVER_IP}:8080/webhook"
echo "  Health: http://${SERVER_IP}:8080/health"
echo "  Metrics: http://${SERVER_IP}:9090/metrics"
echo
echo "Configure Uptime Kuma webhook to: http://${SERVER_IP}:8080/webhook"
echo