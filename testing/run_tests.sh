#!/usr/bin/env bash
set -euo pipefail

PASSED=0
FAILED=0
REPORT="testing/results/report-$(date +%Y%m%d-%H%M%S).json"

assert_http() {
    local exp="$1"; local url="$2"; local desc="$3"
    local act=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 5 "$url")
    if [[ "$act" == "$exp" ]]; then
        echo "  ✓ $desc"; ((PASSED++))
    else
        echo "  ✗ $desc (expected $exp, got $act)"; ((FAILED++))
    fi
}

assert_log() {
    local file="$1"; local pattern="$2"; local desc="$3"
    if grep -q "$pattern" "$file" 2>/dev/null; then
        echo "  ✓ $desc"; ((PASSED++))
    else
        echo "  ✗ $desc (no '$pattern' in $file)"; ((FAILED++))
    fi
}

echo "--- Testing WAF (SQLi, XSS) ---"
assert_http "403" "https://192.168.56.20/DVWA/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271" "Classic SQLi blocked"
assert_http "403" "https://192.168.56.20/?name=<script>alert(1)</script>" "XSS blocked"

echo "--- Testing Suricata (Nmap) ---"
truncate -s 0 /var/log/suricata/fast.log 2>/dev/null || true
nmap -sS -p 1-100 192.168.56.20 >/dev/null 2>&1 || true
sleep 2
assert_log "/var/log/suricata/fast.log" "ET SCAN NMAP" "Nmap detected by IDS"

echo "--- Testing Nginx Rate Limiting ---"
RATE_429=$(seq 1 60 | xargs -P 20 -I {} curl -k -s -o /dev/null -w "%{http_code}\n" https://192.168.56.20/ | grep -c "429" || true)
if [[ "$RATE_429" -gt 0 ]]; then
    echo "  ✓ Rate limiting triggered ($RATE_429 hits)"; ((PASSED++))
else
    echo "  ✗ Rate limiting failed"; ((FAILED++))
fi

echo "========================================"
echo "Total: $((PASSED+FAILED)) | Passed: $PASSED | Failed: $FAILED"
echo "{\"passed\": $PASSED, \"failed\": $FAILED}" > "$REPORT"
