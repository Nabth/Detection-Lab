#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "===================================================="
echo "   STARTING FULL SOC LAB ATTACK SIMULATION"
echo "===================================================="

echo -e "\n[PHASE 1] L3/L4 DDoS & Scans (Spoofed IPs)"
bash "$DIR/attack_l34.sh" 192.168.56.20

# --- ПАУЗА ДЛЯ РАЗБАНА NMAP ---
echo -e "\n\033[1;33m-----------------------------------------------------------------\033[0m"
echo -e "Nmap triggered Active Response (Port Scan). Kali IP is banned."
echo -e "To continue to L7 attacks, run on \033[1;32mVictim\033[0m:"
echo -e "  \033[1;32msudo iptables -D INPUT -s 192.168.56.30 -j DROP\033[0m"
echo -e "  \033[1;32msudo iptables -D FORWARD -s 192.168.56.30 -j DROP\033[0m"
echo -e "\033[1;33m-----------------------------------------------------------------\033[0m"
read -p "Press [Enter] AFTER you have unbanned the IP to start L7 phase..."

echo -e "\n[PHASE 2] L7 Web Attacks & Brute Force (Real IP)"
bash "$DIR/attack_l7.sh" https://192.168.56.20

echo -e "\n===================================================="
echo "   SIMULATION COMPLETE"
echo "   1. Check Wazuh Dashboard (last 15 mins)"
echo "   2. Check Telegram"
echo "===================================================="
