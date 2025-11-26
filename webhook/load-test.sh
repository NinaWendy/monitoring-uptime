#!/bin/bash
# Load testing script for webhook service

set -euo pipefail

WEBHOOK_URL="${1:-http://localhost:8080/webhook}"
TOTAL_REQUESTS="${2:-10000}"
CONCURRENT="${3:-100}"

echo "Load Testing Uptime Kuma Webhook"
echo "================================="
echo "URL: $WEBHOOK_URL"
echo "Total Requests: $TOTAL_REQUESTS"
echo "Concurrent: $CONCURRENT"
echo

# Sample payload
PAYLOAD='{
  "heartbeat": {
    "monitorID": 1,
    "status": 1,
    "time": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "msg": "200 - OK",
    "ping": 45.23,
    "important": false,
    "duration": 30,
    "down": 0,
    "up": 100
  },
  "monitor": {
    "id": 1,
    "name": "Test Monitor",
    "url": "https://example.com",
    "hostname": "example.com",
    "port": 443,
    "type": "http",
    "interval": 60
  },
  "msg": "Test message"
}'

# Use Apache Bench if available
if command -v ab &> /dev/null; then
    echo "$PAYLOAD" > /tmp/webhook-payload.json
    ab -n "$TOTAL_REQUESTS" -c "$CONCURRENT" -p /tmp/webhook-payload.json \
       -T "application/json" "$WEBHOOK_URL"
    rm /tmp/webhook-payload.json

# Otherwise use curl in parallel
else
    echo "Apache Bench not found, using curl (install ab for better results)"
    
    for i in $(seq 1 $TOTAL_REQUESTS); do
        (curl -s -X POST "$WEBHOOK_URL" \
              -H "Content-Type: application/json" \
              -d "$PAYLOAD" > /dev/null) &
        
        # Limit concurrency
        if [ $((i % CONCURRENT)) -eq 0 ]; then
            wait
        fi
    done
    wait
    
    echo "Load test complete!"
fi
