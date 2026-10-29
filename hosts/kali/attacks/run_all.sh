#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(dirname "$0")/../.."
RUN_DIR="$BASE_DIR/reports/run-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN_DIR"

TIMELINE="$RUN_DIR/timeline.txt"
echo "Attack Run: $(date -Iseconds)" > "$TIMELINE"
echo "----------------------------------------" >> "$TIMELINE"

log_event() {
    echo "[$(date +%H:%M:%S)] $1" | tee -a "$TIMELINE"
}

log_event "Starting DDoS Attack Suite"
bash "$BASE_DIR/lab/attacks/attack_ddos.sh"
log_event "DDoS Attack Suite finished"
sleep 3

log_event "Starting SQLi Attack Suite"
bash "$BASE_DIR/lab/attacks/attack_sqli.sh"
log_event "SQLi Attack Suite finished"
sleep 3

log_event "Starting OWASP Attack Suite"
bash "$BASE_DIR/lab/attacks/attack_owasp.sh"
log_event "OWASP Attack Suite finished"

echo "----------------------------------------" >> "$TIMELINE"
echo "All attacks completed. Timeline saved to: $TIMELINE"
