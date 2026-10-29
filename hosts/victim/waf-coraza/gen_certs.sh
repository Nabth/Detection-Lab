#!/usr/bin/env bash
set -euo pipefail
CERT_DIR="$(dirname "$0")/certs"
mkdir -p "$CERT_DIR"
if [[ ! -f "$CERT_DIR/cert.pem" ]]; then
    openssl req -x509 -newkey rsa:4096 -keyout "$CERT_DIR/key.pem" \
        -out "$CERT_DIR/cert.pem" -days 365 -nodes -subj "/CN=192.168.56.20"
    chmod 640 "$CERT_DIR/key.pem"
    chmod 644 "$CERT_DIR/cert.pem"
    echo "[+] Certs generated in $CERT_DIR"
else
    echo "[*] Certs already exist"
fi
