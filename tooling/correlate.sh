#!/usr/bin/env bash
set -euo pipefail

IP="${1:?Usage: $0 <IP>}"
TMP_TSV=$(mktemp)

# Собираем данные из трех источников
python3 "$(dirname "$0")/flatten_json.py" suricata /var/log/suricata/eve.json > "$TMP_TSV" 2>/dev/null || true
python3 "$(dirname "$0")/flatten_json.py" coraza /var/log/coraza/audit/audit.log >> "$TMP_TSV" 2>/dev/null || true
python3 "$(dirname "$0")/flatten_json.py" wazuh /var/ossec/logs/alerts/alerts.json >> "$TMP_TSV" 2>/dev/null || true

echo "## Attack Timeline for \`$IP\`"
echo ""
echo "| Time | Type | Description |"
echo "|------|------|-------------|"

# Ищем IP во втором столбце, сортируем по времени (первый столбец)
awk -F'\t' -v ip="$IP" 'NR>1 && $2==ip {print $1"\t"$5"\t"$7}' "$TMP_TSV" \
    | sort | uniq | \
    awk -F'\t' '{printf "| %s | **%s** | %s |\n", $1, $2, $3}'

rm -f "$TMP_TSV"
