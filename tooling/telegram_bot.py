#!/usr/bin/env python3
"""
SOC Lab notifier — Wazuh Integration for Telegram.

Called by Wazuh Manager automatically via <integration> block in ossec.conf.
Wazuh passes: argv = [script_name, alert_file_path, api_key, hook_url]

Env (loaded from these paths):
    TELEGRAM_TOKEN     — bot token
    TELEGRAM_CHAT_ID   — target chat id
    TELEGRAM_PROXY_URL — optional Cloudflare Worker
"""
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

import telebot

# --- env loading with quote stripping ---------------------------------------
def _load_env(path: Path) -> None:
    try:
        if not path.exists():
            return
        content = path.read_text(encoding="utf-8")
    except (PermissionError, OSError):
        return  # silently skip unreadable paths
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip().strip('"').strip("'")
        os.environ.setdefault(k.strip(), v)

for candidate in (
    Path("/etc/soc-lab/telegram.env"),          # current location
    Path("/var/ossec/etc/integrations.env"),    # Wazuh standard
    Path.home() / "soc-detection-lab" / ".env", # project fallback
):
    _load_env(candidate)

TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
PROXY_URL = os.getenv("TELEGRAM_PROXY_URL")

if PROXY_URL:
    telebot.apihelper.API_URL = PROXY_URL

# --- mappings ---------------------------------------------------------------
CWE_MAP = {
    "sqli":  ("CWE-89",  "SQL Injection",             9.8),
    "xss":   ("CWE-79",  "Cross-Site Scripting",      6.1),
    "ddos":  ("CWE-400", "Resource Exhaustion",       7.5),
    "scan":  ("CWE-200", "Information Exposure",      5.3),
    "brute": ("CWE-307", "Excessive Auth Attempts",   8.1),
    "other": ("CWE-20",  "Improper Input Validation", 5.0),
}

MITRE_TEXT = {
    "T1190":     "Exploit Public-Facing App",
    "T1498":     "Network DoS",
    "T1498.001": "Direct Network Flood",
    "T1498.002": "Reflection Amplification",
    "T1110":     "Brute Force",
    "T1046":     "Network Service Discovery",
    "T1059.007": "JavaScript",
    "T1189":     "Drive-by Compromise",
    "T1595":     "Active Scanning",
}

AR_RULES = {
    "100103", "100200", "100201", "100202", "100203",
    "100204", "100205", "100206", "100207", "100300",
}


def classify(a):
    r = a.get("rule", {}) or {}
    g = [x.lower() for x in r.get("groups", [])]
    d = (r.get("description") or "").lower()
    if "sql_injection" in g or "sql" in d:
        return "sqli"
    if "xss" in g or "xss" in d or "cross-site" in d:
        return "xss"
    if any(x in g for x in ("ddos", "syn_flood", "udp_flood", "icmp_flood",
                             "ack_flood", "rst_flood")):
        return "ddos"
    if any(x in g for x in ("scan", "port_scan", "tcp_anomaly")) or "scan" in d:
        return "scan"
    if any(x in g for x in ("brute_force", "authentication_failed")) or "brute" in d:
        return "brute"
    return "other"


def extract_src_ip(a):
    d = a.get("data", {}) or {}
    for k in ("srcip", "src_ip"):
        if d.get(k):
            return str(d[k])
    tx = d.get("transaction") or {}
    if tx.get("client_ip"):
        return str(tx["client_ip"])
    al = d.get("alert") or {}
    if al.get("src_ip"):
        return str(al["src_ip"])
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", a.get("full_log", ""))
    return m.group(1) if m else "?"


def severity_badge(level):
    if level >= 12: return "🚨 CRITICAL"
    if level >= 10: return "🔴 HIGH"
    if level >= 7:  return "🟠 MEDIUM"
    return "🟡 LOW"


def format_alert(a):
    r = a.get("rule", {}) or {}
    level = int(r.get("level", 0))
    rule_id = str(r.get("id", ""))
    kind = classify(a)
    cwe, name, cvss = CWE_MAP[kind]

    mitre_ids = (r.get("mitre") or {}).get("id") or []
    mitre_id = mitre_ids[0] if mitre_ids else ""
    mitre_line = f"MITRE {mitre_id}"
    if mitre_id in MITRE_TEXT:
        mitre_line += f" {MITRE_TEXT[mitre_id]}"

    src = extract_src_ip(a)
    dst = a.get("agent", {}).get("ip", "?")
    agent = a.get("agent", {}).get("name", "?")

    ts_raw = a.get("timestamp", "")
    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        ts = ts_raw

    groups = [g.lower() for g in r.get("groups", [])]
    desc = r.get("description", "")

    lines = [
        f"{severity_badge(level)} | Wazuh L{level}",
        "",
        f"🎯 {name} ({cwe})",
        f"📈 CVSS {cvss} | {mitre_line}",
        "",
        f"🌐 {src} → {dst}",
        f"🛡️ {desc}",
    ]

    if rule_id in AR_RULES or "active_response" in groups:
        lines.append("🔧 Active Response: IP banned for 600s")
    elif "429" in desc:
        lines.append("🔧 Rate limited (429)")

    lines += ["", f"⏰ {ts}", f"👤 Agent: {agent}"]
    return "\n".join(lines)


def main():
    # Mode A: called manually (testing)
    if len(sys.argv) >= 3 and sys.argv[1] == "--alert-file":
        path = Path(sys.argv[2])
    # Mode B: called by Wazuh Integration
    # argv = [script, alert_file, api_key, hook_url]
    elif len(sys.argv) >= 2 and Path(sys.argv[1]).exists():
        path = Path(sys.argv[1])
    else:
        sys.exit("Usage: telegram_bot.py <alert.json> | --alert-file <alert.json>")

    try:
        alert = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"Cannot read alert: {e}")

    if not TOKEN or not CHAT_ID:
        sys.exit("TELEGRAM_TOKEN / TELEGRAM_CHAT_ID not set")

    bot = telebot.TeleBot(TOKEN)
    try:
        bot.send_message(CHAT_ID, format_alert(alert), disable_web_page_preview=True)
        print("[+] Sent")
    except Exception as e:
        sys.exit(f"Send failed: {e}")


if __name__ == "__main__":
    main()
