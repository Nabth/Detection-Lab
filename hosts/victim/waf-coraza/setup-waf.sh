#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "[*] Starting OWASP Coraza WAF (Nginx + CRS)..."

# 1. Создаём выделенную группу для логов (если её нет)
if ! getent group waf-logs >/dev/null; then
    sudo groupadd -g 2001 waf-logs
fi

# 2. Настраиваем права на логи
sudo mkdir -p /var/log/coraza/audit
sudo chown -R root:waf-logs /var/log/coraza
sudo chmod -R 775 /var/log/coraza
sudo find /var/log/coraza -type f -exec chmod 664 {} \;
sudo chmod g+s /var/log/coraza /var/log/coraza/audit

# 3. Генерируем сертификаты (если их нет)
if [ ! -f certs/cert.pem ]; then
    mkdir -p certs
    openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem \
        -days 365 -nodes -subj "/CN=192.168.56.20"
fi

# 4. Права на сертификаты (Least Privilege)
sudo chown $USER:waf-logs certs/key.pem certs/cert.pem
chmod 640 certs/key.pem
chmod 644 certs/cert.pem

# 5. Запускаем контейнер
docker run -d \
  --name coraza-waf \
  --restart unless-stopped \
  --group-add 2001 \
  -p 443:443 \
  -p 80:80 \
  -e BACKEND=192.168.56.20:8080 \
  -e SSL_PORT=443 \
  -e SSL_CERT_FILE=/etc/ssl/certs/cert.pem \
  -e SSL_CERT_KEY_FILE=/etc/ssl/certs/key.pem \
  -e ACCESSLOG=/var/log/coraza/access.log \
  -e ERRORLOG=/var/log/coraza/error.log \
  -v "$(pwd)/certs/cert.pem:/etc/ssl/certs/cert.pem:ro" \
  -v "$(pwd)/certs/key.pem:/etc/ssl/certs/key.pem:ro" \
  -v "$(pwd)/override.conf:/opt/coraza/config.d/override.conf:ro" \
  -v "$(pwd)/custom-nginx.conf:/templates/nginx.conf:ro" \
  -v /var/log/coraza:/var/log/coraza \
  ghcr.io/coreruleset/coraza-crs:nginx

echo "[+] Coraza WAF started on ports 80 (redirect) and 443 (HTTPS)."
