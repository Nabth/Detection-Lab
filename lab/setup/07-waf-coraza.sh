#!/usr/bin/env bash
set -euo pipefail

echo "[*] Creating log directories..."
sudo mkdir -p /var/log/coraza/audit
sudo chmod -R 777 /var/log/coraza

echo "[*] Starting OWASP Coraza WAF (Caddy + CRS)..."
docker run -d \
  --name coraza-waf \
  --restart unless-stopped \
  -p 8080:8080 \
  -e BACKEND=192.168.56.20:80 \
  -e CORAZA_SECRULEENGINE=On \
  -e CORAZA_SECREQUESTBODYACCESS=On \
  -e CORAZA_AUDIT_ENGINE=On \
  -e CORAZA_AUDIT_LOG_TYPE=Serial \
  -e CORAZA_AUDIT_STORAGE_DIR=/var/log/coraza/audit \
  -e CORAZA_AUDIT_LOG=/var/log/coraza/audit/audit.log \
  -v /var/log/coraza:/var/log/coraza \
  ghcr.io/coreruleset/coraza-crs:caddy-alpine

echo "[+] Coraza WAF started on port 8080."
