#!/usr/bin/env python3
"""
SOC Lab notifier — Wazuh Integration for Telegram.
Includes Alert Deduplication (by Attack Type & IP), URL decoding, and CWE mapping.
"""
import json
import os
import re
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

import requests

# --- env loading ---
def _load_env(path: Path) -> None:
    try:
        if not path.exists():
            return
        content = path.read_text(encoding="utf-8")
    except (PermissionError, OSError):
        return
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip().strip('"').strip("'")
        os.environ.setdefault(k.strip(), v)

for candidate in (
    Path("/etc/soc-lab/telegram.env"),
    Path("/var/ossec/etc/integrations.env"),
    Path.home() / "soc-detection-lab" / ".env",
):
    _load_env(candidate)

TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
PROXY_URL = os.getenv("TELEGRAM_PROXY_URL")

# --- mappings ---
CWE_MAP = {
    "sqli":    ("CWE-89",  "SQL Injection",             9.8),
    "xss":     ("CWE-79",  "Cross-Site Scripting",      6.1),
    "cmdinj":  ("CWE-78",  "OS Command Injection",      9.8),
    "lfi":     ("CWE-98",  "Local File Inclusion",      7.5),
    "ddos_l3": ("CWE-400", "Network DDoS (L3/L4)",      7.5),
    "ddos_l7": ("CWE-400", "HTTP Flood (L7)",           7.5),
    "scan":    ("CWE-200", "Information Exposure",      5.3),
    "brute":   ("CWE-307", "Excessive Auth Attempts",   8.1),
    "other":   ("CWE-20",  "Improper Input Validation", 5.0),
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

AR_TIMEOUTS = {
    "100203": 300,
}

# --- Anti-Spam Cache ---
CACHE_FILE = Path("/tmp/wazuh_tg_cache.json")
COOLDOWN = 300  # 5 minutes

def is_spam(kind, srcip):
    if not srcip or srcip == "?":
        return False

    if not CACHE_FILE.exists():
        CACHE_FILE.write_text("{}")
    try:
        cache = json.loads(CACHE_FILE.read_text())
    except Exception:
        cache = {}
        
    key = f"{kind}:{srcip}"
    now = time.time()
    
    if key in cache and (now - cache[key]) < COOLDOWN:
        return True
        
    cache[key] = now
    cache = {k: v for k, v in cache.items() if now - v < COOLDOWN}
    
    try:
        CACHE_FILE.write_text(json.dumps(cache))
    except Exception:
        pass
    return False

# --- logic ---
def classify(a):
    r = a.get("rule", {}) or {}
    g = [x.lower() for x in r.get("groups", [])]
    d = (r.get("description") or "").lower()
    uri = str(a.get("data", {}).get("url", "")) + str(a.get("full_log", ""))
    uri = uri.lower()
    
    if "sql_injection" in g or "sql" in d or "union" in uri or "select" in uri:
        return "sqli"
    if "xss" in g or "xss" in d or "cross-site" in d or "<script>" in uri:
        return "xss"
    if "whoami" in uri or "%3b" in uri or "cmd" in g or "shell" in uri:
        return "cmdinj"
    if "etc/passwd" in uri or "../" in uri or "lfi" in g:
        return "lfi"
    if any(x in g for x in ("syn_flood", "udp_flood", "icmp_flood", "ack_flood", "rst_flood", "ddos")) or "flood" in d:
        if "nginx" in g or "web" in g or "429" in d:
            return "ddos_l7"
        return "ddos_l3"
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
    
    full_log = a.get("full_log", "")
    m = re.search(r'"src_ip":"(\d{1,3}(?:\.\d{1,3}){3})"', full_log)
    if m: return m.group(1)
    m = re.search(r'client:\s*(\d{1,3}(?:\.\d{1,3}){3})', full_log)
    if m: return m.group(1)
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", full_log)
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
    
    # Декодируем URL, чтобы убрать мусор вроде %3B и %3C
    desc = urllib.parse.unquote(r.get("description", ""))

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
        timeout = AR_TIMEOUTS.get(rule_id, 600)
        lines.append(f"🔧 Active Response: IP banned for {timeout}s")
    elif "429" in desc:
        lines.append("🔧 Rate limited (429)")

    lines += ["", f"⏰ {ts}", f"👤 Agent: {agent}"]
    return "\n".join(lines)

def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "--alert-file":
        path = Path(sys.argv[2])
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

    rule_id = str(alert.get("rule", {}).get("id", ""))
    if rule_id == "651":
        print("[-] Skipping Active Response confirmation (651)")
        sys.exit(0)

    kind = classify(alert)
    src_ip = extract_src_ip(alert)
    
    # Для кэша объединяем ACK/SYN и HTTP Flood в один тип
    cache_kind = "ddos" if kind in ("ddos_l3", "ddos_l7") else kind
    
    if is_spam(cache_kind, src_ip):
        print(f"[-] Suppressed duplicate alert for {kind} from {src_ip}")
        sys.exit(0)

    if PROXY_URL:
        url = PROXY_URL.format(TOKEN, "sendMessage")
    else:
        url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"

    payload = {
        "chat_id": CHAT_ID,
        "text": format_alert(alert),
        "disable_web_page_preview": True
    }
    
    try:
        r = requests.post(url, json=payload, timeout=15)
        r.raise_for_status()
        print("[+] Sent via requests")
    except Exception as e:
        sys.exit(f"Send failed: {e}")

if __name__ == "__main__":
    main()
