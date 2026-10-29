#!/usr/bin/env python3
import json
import sys
from pathlib import Path

HEADER = ["timestamp", "src_ip", "dest_ip", "dest_port", "attack_type", "severity", "description"]

def classify(sig: str) -> str:
    s = sig.lower()
    if "sql" in s: return "SQLI"
    if "xss" in s: return "XSS"
    if "scan" in s: return "SCAN"
    if any(k in s for k in ("flood", "dos", "ddos")): return "DDOS"
    if "brute" in s: return "BRUTE"
    return "OTHER"

def parse_suricata(line: str):
    try: obj = json.loads(line)
    except: return None
    if obj.get("event_type") != "alert": return None
    a = obj.get("alert", {})
    return [obj.get("timestamp",""), obj.get("src_ip",""), obj.get("dest_ip",""),
            str(obj.get("dest_port","")), classify(a.get("signature","")),
            str(a.get("severity","")), a.get("signature","")]

def parse_coraza(line: str):
    try: obj = json.loads(line)
    except: return None
    tx = obj.get("transaction", {})
    if not tx.get("is_interrupted"): return None
    desc = "WAF blocked"
    for m in obj.get("messages", []):
        e = m.get("error_message", "")
        if "SQL" in e: desc = "SQLi"; break
        if "XSS" in e: desc = "XSS"; break
    return [tx.get("timestamp",""), tx.get("client_ip",""), "",
            str(tx.get("host_port","")), classify(desc), "HIGH", desc]

def parse_wazuh(line: str):
    try: obj = json.loads(line)
    except: return None
    r = obj.get("rule", {})
    if r.get("level", 0) < 7: return None
    d = r.get("description", "")
    src = obj.get("data", {}).get("srcip", "") or obj.get("agent", {}).get("ip", "")
    return [obj.get("timestamp",""), src, "", "", classify(d), str(r.get("level","")), d]

PARSERS = {"suricata": parse_suricata, "coraza": parse_coraza, "wazuh": parse_wazuh}

if len(sys.argv) != 3 or sys.argv[1] not in PARSERS:
    print(f"Usage: {sys.argv[0]} <suricata|coraza|wazuh> <file>", file=sys.stderr)
    sys.exit(1)

p = PARSERS[sys.argv[1]]
path = Path(sys.argv[2])
if not path.exists(): sys.exit(0)

print("\t".join(HEADER))
with path.open("r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        row = p(line)
        if row: print("\t".join(row))
