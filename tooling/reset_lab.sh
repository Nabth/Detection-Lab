#!/usr/bin/env bash
set -euo pipefail

echo "[*] Resetting lab state..."

# 1. Flush custom DDOS chain
if iptables -L CUSTOM_DDOS >/dev/null 2>&1; then
    iptables -F CUSTOM_DDOS
fi

# 2. Restart Wazuh Agent (forget bans)
systemctl restart wazuh-agent
sleep 2

# 3. Truncate logs
truncate -s 0 /var/log/suricata/eve.json 2>/dev/null || true
truncate -s 0 /var/log/suricata/fast.log 2>/dev/null || true
truncate -s 0 /var/log/coraza/access.log 2>/dev/null || true

# 4. Restart Docker (restore NAT/iptables)
systemctl restart docker
sleep 3

# 5. Unban all in Fail2Ban
fail2ban-client unban --all 2>/dev/null || true

echo "[+] Lab is clean."
