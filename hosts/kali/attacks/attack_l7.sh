#!/usr/bin/env bash
set -euo pipefail

TARGET_URL="${1:-https://192.168.56.20}"

echo -e "\033[1;33m[*] Starting L7 Attacks against $TARGET_URL\033[0m"

# =====================================================================
# PHASE 1: Web Attacks (WAF blocks)
# =====================================================================
echo -e "\n\033[1;36m[PHASE 1] OWASP Top 10 & WAF Evasion\033[0m"

echo "[+] SQL Injection (5 payloads)"
PAYLOADS=(
  "/?id=1%27%20OR%20%271%27=%271"
  "/?id=1%27%20UNION%20SELECT%20user,password%20FROM%20users--"
  "/?id=1%27%20AND%20extractvalue(1,concat(0x7e,database()))--"
  "/?id=1%27%20AND%20SLEEP(5)--"
  "/?id=1%27;%20DROP%20TABLE%20users--"
)
for p in "${PAYLOADS[@]}"; do
    curl -k -s -o /dev/null -w "  Status: %{http_code}\n" "$TARGET_URL$p"
    sleep 1
done

echo "[+] XSS (Reflected)"
curl -k -s -o /dev/null -w "  Status: %{http_code}\n" "$TARGET_URL/?name=%3Cscript%3Ealert(1)%3C/script%3E"
sleep 1

echo "[+] Command Injection"
curl -k -s -o /dev/null -w "  Status: %{http_code}\n" "$TARGET_URL/?ip=127.0.0.1%3Bwhoami"
sleep 1

echo "[+] Local File Inclusion (LFI)"
curl -k -s -o /dev/null -w "  Status: %{http_code}\n" "$TARGET_URL/?file=../../../../etc/passwd"
sleep 1

echo "[+] Custom WAF: Obfuscated SQLi"
curl -k -s -o /dev/null -w "  Status: %{http_code}\n" "$TARGET_URL/?id=1%27%20UNION/**/SELECT%20user--"
sleep 1

echo "[+] Custom WAF: Double URL Encoding"
curl -k -s -o /dev/null -w "  Status: %{http_code}\n" "$TARGET_URL/?id=1%2527"
sleep 1

echo "[+] Custom WAF: SQLMap User-Agent"
curl -k -s -o /dev/null -w "  Status: %{http_code}\n" -A "sqlmap/1.7.2#stable" "$TARGET_URL/"
sleep 1

# =====================================================================
# PHASE 2: HTTP Flood (Banning Attack)
# =====================================================================
echo -e "\n\033[1;31m[PHASE 2] HTTP Flood (Triggers Active Response)\033[0m"
echo "[!] WARNING: Your real IP (192.168.56.30) will be banned!"

echo "[+] HTTP Flood (Expect 429)"
seq 1 60 | xargs -P 20 -I {} curl -k -s -o /dev/null "$TARGET_URL/"

echo -e "\n\033[1;33m-----------------------------------------------------------------\033[0m"
echo -e "HTTP Flood triggered Active Response. Kali IP is banned for 600s."
echo -e "To continue, run these commands on \033[1;32mVictim\033[0m:"
echo -e "  \033[1;32msudo iptables -D INPUT -s 192.168.56.30 -j DROP\033[0m"
echo -e "  \033[1;32msudo iptables -D FORWARD -s 192.168.56.30 -j DROP\033[0m"
echo -e "\033[1;33m-----------------------------------------------------------------\033[0m"
read -p "Press [Enter] AFTER you have unbanned the IP to finish..."

echo -e "\n\033[1;32m[+] L7 Suite Finished.\033[0m"
