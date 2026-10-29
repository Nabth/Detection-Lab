#!/usr/bin/env bash
set -euo pipefail

echo "========================================"
echo "SOC Lab Health Check"
echo "========================================"
FAILED=0
WARNED=0

# Проверяем, есть ли passwordless sudo
HAS_SUDO=0
if sudo -n true 2>/dev/null; then
    HAS_SUDO=1
fi

check() {
    local name="$1"; local cmd="$2"; local needs_sudo="${3:-no}"

    if [[ "$needs_sudo" == "yes" && "$HAS_SUDO" -eq 0 ]]; then
        echo "  ⚠ $name (requires sudo, run: sudo bash $0)"
        WARNED=$((WARNED + 1))
        return
    fi

    if eval "$cmd" >/dev/null 2>&1; then
        echo "  ✓ $name"
    else
        echo "  ✗ $name"
        FAILED=$((FAILED + 1))
    fi
}

check "WAF (HTTPS 443)"              "curl -k -s --max-time 3 -o /dev/null -w '%{http_code}' https://192.168.56.20/ | grep -q 200"
check "Apache/DVWA (HTTP 8080)"      "curl -s --max-time 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ | grep -q 200"
check "Suricata service"             "systemctl is-active --quiet suricata"
check "Wazuh Agent service"          "systemctl is-active --quiet wazuh-agent"
check "Docker container (coraza-waf)" "docker ps | grep -q coraza-waf"
check "iptables CUSTOM_DDOS chain"   "sudo -n iptables -L CUSTOM_DDOS -n" "yes"
check "Fail2Ban service"             "systemctl is-active --quiet fail2ban"

echo "========================================"
if [[ "$FAILED" -eq 0 && "$WARNED" -eq 0 ]]; then
    echo "✅ All services alive"
    exit 0
elif [[ "$FAILED" -eq 0 ]]; then
    echo "⚠ All checks pass, but $WARNED skipped (need sudo)"
    exit 0
else
    echo "❌ $FAILED failed, $WARNED skipped (need sudo)"
    exit 1
fi
