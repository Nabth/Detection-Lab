#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "===================================================="
echo "   STARTING FULL SOC LAB ATTACK SIMULATION"
echo "===================================================="

echo -e "\n[PHASE 1] L3/L4 DDoS & Scans (Spoofed IPs)"
bash "$DIR/attack_l34.sh" 192.168.56.20

echo -e "\n[PHASE 2] L7 Web Attacks & Brute Force (Interactive)"
bash "$DIR/attack_l7.sh" https://192.168.56.20 192.168.56.20

echo -e "\n===================================================="
echo "   SIMULATION COMPLETE"
echo "   1. Check Wazuh Dashboard (last 15 mins)"
echo "   2. Check Telegram"
echo "===================================================="
