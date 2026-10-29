#!/usr/bin/env bash
set -euo pipefail

ATTACKS_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$ATTACKS_DIR/../../.." && pwd)"
RUN_DIR="$BASE_DIR/reports/run-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN_DIR"

TIMELINE="$RUN_DIR/timeline.txt"
{
    echo "Attack Run: $(date -Iseconds)"
    echo "Attacker: $(hostname) / $(hostname -I | awk '{print $1}')"
    echo "Target:   ${TARGET:-192.168.56.20}"
    echo "----------------------------------------"
} > "$TIMELINE"

log_event() {
    echo "[$(date +%H:%M:%S)] $1" | tee -a "$TIMELINE"
}

run_attack() {
    local name="$1"; local script="$2"
    log_event "Starting: $name"
    if [[ ! -f "$ATTACKS_DIR/$script" ]]; then
        log_event "SKIP: $script not found"
        return
    fi
    if bash "$ATTACKS_DIR/$script"; then
        log_event "OK: $name"
    else
        log_event "FAIL: $name (exit $?)"
    fi
    echo "" >> "$TIMELINE"
    sleep 2
}

log_event "=== Attack Suite Start ==="

run_attack "DDoS Suite"   "attack_ddos.sh"
run_attack "SQLi Suite"   "attack_sqli.sh"
run_attack "OWASP Suite"  "attack_owasp.sh"

log_event "=== Attack Suite Complete ==="
echo "----------------------------------------" >> "$TIMELINE"
echo ""
echo "[+] Timeline: $TIMELINE"
