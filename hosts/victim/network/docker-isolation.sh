#!/usr/bin/env bash
set -euo pipefail

# This script applies the DOCKER-USER iptables rules manually.
# It serves as a fallback/backup method to ensure the rules are applied 
# immediately without needing to restart UFW.
# The persistent configuration is documented in network/README.md and 
# is applied via /etc/ufw/after.rules upon `ufw reload`.

echo "[*] Applying DOCKER-USER rules..."
sudo iptables -F DOCKER-USER 2>/dev/null || true

sudo iptables -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
sudo iptables -A DOCKER-USER -p tcp --dport 443 -j RETURN
sudo iptables -A DOCKER-USER -p tcp --dport 80 -j RETURN
sudo iptables -A DOCKER-USER -s 172.28.0.2 -d 172.28.0.1 -p tcp --dport 8080 -j RETURN
sudo iptables -A DOCKER-USER -j DROP

echo "[+] DOCKER-USER rules applied."
