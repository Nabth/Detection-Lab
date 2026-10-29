#!/usr/bin/env python3
"""
SOC Lab: alert formatter + Telegram sender.

Used by:
  - hosts/wazuh-server/wazuh/integrations/custom-telegram.py (Wazuh Integration)
  - tooling/cli.py (manual report notifications)

Env (loaded from /var/ossec/etc/integrations.env or standard env):
  TELEGRAM_TOKEN    — bot token (required)
  TELEGRAM_CHAT_ID  — target chat id (required)
  TELEGRAM_PROXY_URL — optional custom API base (e.g. Cloudflare Worker)
"""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

import telebot

# --- Mapping: attack type → CWE / CVSS / MITRE -------------------------------

CWE_MAP = {
    "sqli":  {"cwe": "CWE-89",  "name": "SQL Injection",           "cvss": 9.8, "mitre": "T1190"},
    "xss":   {"cwe": "CWE-79",  "name": "Cross-Site Scripting",    "cvss": 6.1, "mitre": "T1059.007"},
    "ddos":  {"cwe": "CWE-400", "name": "Resource Exhaustion",     "cvss": 7.5, "mitre": "T1498.001"},
    "scan":  {"cwe": "CWE-200", "name": "Information Exposure",    "cvss": 5.3, "mitre": "T1046"},
    "brute": {"cwe": "CWE-307", "name": "Excessive Auth Attempts", "cvss": 8.1, "mitre": "T1110"},
    "other": {"cwe": "CWE-20",  "name": "Improper Input Validation", "cvss": 5.0, "mitre": "T1190"},
}

SEVERITY_BY_LEVEL = [
    (13, "🚨 CRITICAL"),
    (10, "🔴 HIGH"),
    (7,  "🟠 MEDIUM"),
    (0,  "🟡 LOW"),
]


# --- Classification ----------------------------------------------------------

def classify(alert: dict) -> str:
    """Return one of: sqli | xss | ddos | scan | brute | other."""
    rule = alert.get("rule", {})
    groups = [g.lower() for g in rule.get("groups", [])]
    desc = (rule.get("description") or "").lower()

    if "sql_injection" in groups or "sqli" in desc or "sql injection" in desc:
        return "sqli"
    if "xss" in groups or "cross-site" in desc or "xss" in desc:
        return "xss"
    if any(g in groups for g in ("ddos", "syn_flood", "udp_flood", "icmp_flood",
                                  "ack_flood", "rst_flood")):
        return "ddos"
    if any(g in groups for g in ("scan", "port_scan", "tcp_anomaly")) or "scan" in desc:
        return "scan"
    if any(g in groups for g in ("brute_force", "authentication_failed")) or "brute" in desc:
        return "brute"
    return "other"


def severity_badge(level: int) -> str:
    for threshold, badge in SEVERITY_BY_LEVEL:
        if level >= threshold:
            return badge
    return "🟡 LOW"


# --- Extraction helpers -----------------------------------------------------

def _src_ip(alert: dict) -> str:
    data = alert.get("data", {}) or {}
    # разные источники кладут IP в разные места
    for key in ("srcip", "src_ip"):
        if data.get(key):
            return str(data[key])
    tx = data.get("transaction") or {}
    if tx.get("client_ip"):
        return str(tx["client_ip"])
    a = data.get("alert") or {}
    if a.get("src_ip"):
        return str(a["src_ip"])
    # fallback: регекс по full_log — там точно есть IP
    import re
    m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', alert.get("full_log", ""))
    return m.group(1) if m else "?"


def _action_taken(alert: dict) -> str | None:
    """Пытаемся понять, что сделала защита."""
    desc = (alert.get("rule", {}).get("description") or "").lower()
    groups = [g.lower() for g in alert.get("rule", {}).get("groups", [])]
    if "attack blocked" in desc or "blocked" in desc:
        return "WAF blocked"
    if "active_response" in groups or "firewall-drop" in desc or "banned" in desc:
        return "IP banned (Active Response)"
    if "rate" in desc or "429" in desc:
        return "Rate limited (429)"
    if "brute" in desc or "brute_force" in groups:
        return "Brute force detected"
    return None


# --- Formatter --------------------------------------------------------------

def format_alert(alert: dict) -> str:
    """Build a phone-friendly Telegram message from a Wazuh alert."""
    rule = alert.get("rule", {}) or {}
    level = int(rule.get("level", 0))
    kind = classify(alert)
    meta = CWE_MAP[kind]

    src = _src_ip(alert)
    dst = alert.get("agent", {}).get("ip") or "?"
    action = _action_taken(alert)

    mitre_ids = (rule.get("mitre") or {}).get("id") or []
    mitre = meta["mitre"] if not mitre_ids else mitre_ids[0]

    ts_raw = alert.get("timestamp", "")
    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        ts_str = ts_raw

    agent = alert.get("agent", {}).get("name", "?")

    lines = [
        f"{severity_badge(level)} | Wazuh L{level}",
        "",
        f"🎯 {meta['name']} ({meta['cwe']})",
        f"📈 CVSS {meta['cvss']} | MITRE {mitre}",
        "",
        f"🌐 {src} → {dst}",
        f"🛡️ {rule.get('description', 'no description')}",
    ]
    if action:
        lines.append(f"🔧 Action: {action}")
    lines += [
        "",
        f"⏰ {ts_str}",
        f"👤 Agent: {agent}",
    ]
    return "\n".join(lines)


# --- Sender -----------------------------------------------------------------

def _load_env_file(path: Path) -> None:
    """Load KEY=VALUE file into os.environ if not already set."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def _init_bot() -> tuple[telebot.TeleBot, str]:
    # Wazuh Integration runs as `ossec` and may not see user env.
    _load_env_file(Path("/var/ossec/etc/integrations.env"))

    token = os.getenv("TELEGRAM_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        raise RuntimeError("TELEGRAM_TOKEN / TELEGRAM_CHAT_ID not set")

    proxy = os.getenv("TELEGRAM_PROXY_URL")
    if proxy:
        telebot.apihelper.API_URL = proxy

    return telebot.TeleBot(token), chat_id


def send_alert(alert: dict) -> bool:
    """Format + push. Returns True on success. Never raises."""
    try:
        text = format_alert(alert)
        bot, chat_id = _init_bot()
        bot.send_message(chat_id, text, parse_mode=None, disable_web_page_preview=True)
        return True
    except Exception as e:
        print(f"[notifier] send failed: {e}", flush=True)
        return False
