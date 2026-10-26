#!/usr/bin/env bash
set -euo pipefail

echo "[*] Installing and configuring time synchronization (chrony)..."

# Install chrony if not present
if ! command -v chronyc &> /dev/null; then
    sudo apt update -qq
    sudo apt install -y chrony
fi

# Enable and start the service
sudo systemctl enable --now chrony

echo "[*] Current synchronization status:"
chronyc tracking

echo "[+] Done. System time is synchronized."
