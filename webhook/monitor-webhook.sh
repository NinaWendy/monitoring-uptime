#!/bin/bash
# Production monitoring script for webhook service

set -euo pipefail

WEBHOOK_PORT="${WEBHOOK_PORT:-8080}"
METRICS_PORT="${METRICS_PORT:-9094}"
LOG_FILE="/var/log/uptime-kuma/webhook.log"
ALERT_THRESHOLD_BUFFER=8000
ALERT_THRESHOLD_ERRORS=100

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_header() {
    echo "================================================"
    echo "  Uptime Kuma Webhook Service Monitor"
    echo "  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "================================================"
    echo
}

check_service() {
    echo -n "Service Status: "
    if systemctl is-active --quiet uptime-kuma-webhook; then
        echo -e "${GREEN}RUNNING${NC}"
        return 0
    else
        echo -e "${RED}STOPPED${NC}"
        return 1
    fi
}

check_health() {
    echo -n "Health Check: "
    if curl -s -f "http://localhost:${WEBHOOK_PORT}/health" > /dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
        return 0
    else
        echo -e "${RED}FAILED${NC}"
        return 1
    fi
}

get_metrics() {
    if ! curl -s -f "http://localhost:${METRICS_PORT}/metrics" > /tmp/metrics.txt 2>&1; then
        echo -e "${RED}Failed to fetch metrics${NC}"
        return 1
    fi

    echo "Metrics:"
    echo "--------"
    
    # Extract key metrics
    REQUESTS_TOTAL=$(grep "^webhook_requests_total" /tmp/metrics.txt | awk '{print $2}')
    REQUESTS_SUCCESS=$(grep "^webhook_requests_success" /tmp/metrics.txt | awk '{print $2}')
    REQUESTS_FAILURE=$(grep "^webhook_requests_failure" /tmp/metrics.txt | awk '{print $2}')
    LOGS_WRITTEN=$(grep "^webhook_logs_written" /tmp/metrics.txt | awk '{print $2}')
    LOG_ERRORS=$(grep "^webhook_log_write_errors" /tmp/metrics.txt | awk '{print $2}')
    BUFFER_SIZE=$(grep "^webhook_buffer_size" /tmp/metrics.txt | awk '{print $2}')
    BUFFER_DROPPED=$(grep "^webhook_buffer_dropped" /tmp/metrics.txt | awk '{print $2}')
    RATE_LIMIT=$(grep "^webhook_rate_limit_hits" /tmp/metrics.txt | awk '{print $2}')
    BYTES=$(grep "^webhook_bytes_written" /tmp/metrics.txt | awk '{print $2}')
    
    echo "  Requests Total:    $REQUESTS_TOTAL"
    echo "  Requests Success:  $REQUESTS_SUCCESS"
    echo "  Requests Failure:  $REQUESTS_FAILURE"
    echo "  Logs Written:      $LOGS_WRITTEN"
    echo "  Log Errors:        $LOG_ERRORS"
    echo "  Buffer Size:       $BUFFER_SIZE / 10000"
    echo "  Buffer Dropped:    $BUFFER_DROPPED"
    echo "  Rate Limit Hits:   $RATE_LIMIT"
    echo "  Bytes Written:     $(numfmt --to=iec-i --suffix=B $BYTES 2>/dev/null || echo $BYTES)"
    
    # Alerts
    if [ "$BUFFER_SIZE" -gt "$ALERT_THRESHOLD_BUFFER" ]; then
        echo -e "${YELLOW}  ⚠ WARNING: Buffer size high ($BUFFER_SIZE/10000)${NC}"
    fi
    
    if [ "$LOG_ERRORS" -gt "$ALERT_THRESHOLD_ERRORS" ]; then
        echo -e "${RED}  ⚠ ALERT: High log write errors ($LOG_ERRORS)${NC}"
    fi
    
    if [ "$BUFFER_DROPPED" -gt "0" ]; then
        echo -e "${YELLOW}  ⚠ WARNING: Dropped events due to full buffer ($BUFFER_DROPPED)${NC}"
    fi
    
    rm -f /tmp/metrics.txt
}

check_log_file() {
    echo
    echo "Log File:"
    echo "---------"
    if [ -f "$LOG_FILE" ]; then
        SIZE=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null)
        SIZE_HUMAN=$(numfmt --to=iec-i --suffix=B $SIZE 2>/dev/null || echo "$SIZE bytes")
        echo "  Path: $LOG_FILE"
        echo "  Size: $SIZE_HUMAN"
        echo "  Last modified: $(stat -f%Sm "$LOG_FILE" 2>/dev/null || stat -c%y "$LOG_FILE" 2>/dev/null)"
        echo "  Last 5 entries:"
        tail -5 "$LOG_FILE" | jq -r '"\(.timestamp) [\(.monitor_type)] \(.monitor_name) - \(.status)"' 2>/dev/null || tail -5 "$LOG_FILE"
    else
        echo -e "${YELLOW}  Log file not found${NC}"
    fi
}

check_rsyslog() {
    echo
    echo "Rsyslog Status:"
    echo "---------------"
    if systemctl is-active --quiet rsyslog; then
        echo -e "  Status: ${GREEN}RUNNING${NC}"
        
        # Check if rsyslog is processing our logs
        STATE_FILE="/var/spool/rsyslog/uptime-kuma-state"
        if [ -f "$STATE_FILE" ]; then
            echo "  State file exists: Yes"
        else
            echo -e "  State file exists: ${YELLOW}No (rsyslog may not have started reading yet)${NC}"
        fi
    else
        echo -e "  Status: ${RED}STOPPED${NC}"
    fi
}

check_system_resources() {
    echo
    echo "System Resources:"
    echo "-----------------"
    
    # CPU usage
    CPU=$(ps -p $(pgrep -f uptime-kuma-webhook | head -1) -o %cpu= 2>/dev/null || echo "0")
    echo "  CPU Usage: ${CPU}%"
    
    # Memory usage
    MEM=$(ps -p $(pgrep -f uptime-kuma-webhook | head -1) -o %mem= 2>/dev/null || echo "0")
    echo "  Memory Usage: ${MEM}%"
    
    # Goroutines (if available via debug endpoint)
    # GOROUTINES=$(curl -s http://localhost:${METRICS_PORT}/debug/goroutines 2>/dev/null || echo "N/A")
    # echo "  Goroutines: $GOROUTINES"
    
    # File descriptors
    PID=$(pgrep -f uptime-kuma-webhook | head -1)
    if [ -n "$PID" ]; then
        FD_COUNT=$(ls /proc/$PID/fd 2>/dev/null | wc -l || echo "N/A")
        echo "  Open FDs: $FD_COUNT"
    fi
}

# Main execution
print_header

if ! check_service; then
    echo
    echo -e "${RED}Service is not running. Start with: sudo systemctl start uptime-kuma-webhook${NC}"
    exit 1
fi

check_health
echo
get_metrics
check_log_file
check_rsyslog
check_system_resources

echo
echo "================================================"
echo "To view live logs: sudo journalctl -u uptime-kuma-webhook -f"
echo "To view metrics: curl http://localhost:${METRICS_PORT}/metrics"
echo "================================================"
