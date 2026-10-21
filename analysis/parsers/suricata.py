import json
from datetime import datetime
from pathlib import Path
from typing import Iterator
from analysis.core.models import SecurityEvent, AttackType, Severity

def classify_attack(signature: str) -> AttackType:
    sig = signature.lower()
    if any(k in sig for k in ("syn flood", "dos ", "ddos", "flood")):
        return AttackType.DDOS
    if any(k in sig for k in ("sql injection", "sqli", "union select")):
        return AttackType.SQLI
    if "scan" in sig:
        return AttackType.SCAN
    return AttackType.UNKNOWN

def parse_eve(path: Path) -> Iterator[SecurityEvent]:
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            # Нас интересуют только алерты
            if obj.get("event_type") != "alert":
                continue
                
            alert = obj.get("alert", {})
            sig = alert.get("signature", "")
            
            # Преобразуем timestamp из формата Suricata в объект datetime
            ts_str = obj.get("timestamp", "").replace("Z", "+00:00")
            try:
                ts = datetime.fromisoformat(ts_str)
            except ValueError:
                ts = datetime.now()
                
            yield SecurityEvent(
                timestamp=ts,
                source_ip=obj.get("src_ip", ""),
                dest_ip=obj.get("dest_ip"),
                source_port=obj.get("src_port"),
                dest_port=obj.get("dest_port"),
                attack_type=classify_attack(sig),
                signature=sig,
                severity=Severity.HIGH if alert.get("severity") in (1, 2) else Severity.LOW,
                raw=obj
            )
