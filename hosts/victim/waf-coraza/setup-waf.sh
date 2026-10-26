#!/usr/bin/env bash
set -euo pipefail

echo "[*] Starting OWASP Coraza WAF (Nginx + CRS)..."

# 1. Создаем директории для логов и выдаем права (для UID/GID контейнера)
sudo mkdir -p /var/log/coraza/audit
sudo chown -R root:101 /var/log/coraza
sudo chmod 775 /var/log/coraza /var/log/coraza/audit

# 2. Генерируем сертификаты (если их еще нет)
if [ ! -f "$(dirname "$0")/certs/cert.pem" ]; then
    echo "[*] Generating self-signed certificates..."
    mkdir -p "$(dirname "$0")/certs"
    openssl req -x509 -newkey rsa:4096 -keyout "$(dirname "$0")/certs/key.pem" -out "$(dirname "$0")/certs/cert.pem" -days 365 -nodes -subj "/CN=192.168.56.20"
    chmod 640 "$(dirname "$0")/certs/key.pem"
    chmod 644 "$(dirname "$0")/certs/cert.pem"
fi

# 3. Запускаем контейнер с нашим кастомным nginx.conf
docker run -d \
  --name coraza-waf \
  --restart unless-stopped \
  -p 443:443 \
  -e BACKEND=192.168.56.20:80 \
  -e SSL_PORT=443 \
  -e SSL_CERT_FILE=/etc/ssl/certs/cert.pem \
  -e SSL_CERT_KEY_FILE=/etc/ssl/certs/key.pem \
  -e ACCESSLOG=/var/log/coraza/access.log \
  -e ERRORLOG=/var/log/coraza/error.log \
  -v "$(dirname "$0")/certs/cert.pem:/etc/ssl/certs/cert.pem:ro" \
  -v "$(dirname "$0")/certs/key.pem:/etc/ssl/certs/key.pem:ro" \
  -v "$(dirname "$0")/override.conf:/opt/coraza/config.d/override.conf:ro" \
  -v "$(dirname "$0")/custom-nginx.conf:/templates/nginx.conf:ro" \
  -v /var/log/coraza:/var/log/coraza \
  ghcr.io/coreruleset/coraza-crs:nginx

echo "[+] Coraza WAF started on port 443."
