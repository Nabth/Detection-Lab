import json
from datetime import datetime
from pathlib import Path
from typing import Iterator
from analysis.core.models import SecurityEvent, AttackType, Severity

def classify_coraza_attack(messages: list) -> AttackType:
    """Анализирует массив сообщений от CRS и определяет тип атаки."""
    for msg in messages:
        err_msg = msg.get("error_message", "")
        if "SQL Injection" in err_msg:
            return AttackType.SQLI
        if "XSS" in err_msg or "Cross-site Scripting" in err_msg:
            return AttackType.XSS
    return AttackType.UNKNOWN

def parse_coraza(path: Path) -> Iterator[SecurityEvent]:
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            transaction = obj.get("transaction", {})
            if not transaction:
                continue
            
            if not transaction.get("is_interrupted", False):
                continue

            messages = obj.get("messages", [])
            attack_type = classify_coraza_attack(messages)
            
            ts_str = transaction.get("timestamp", "")
            try:
                ts = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S")
            except ValueError:
                ts = datetime.now()

            yield SecurityEvent(
                timestamp=ts,
                source_ip=transaction.get("client_ip", ""),
                dest_ip=transaction.get("server_id"),
                source_port=transaction.get("client_port", 0),
                dest_port=transaction.get("host_port", 443),
                attack_type=attack_type,
                signature="Coraza WAF: Blocked Request",
                severity=Severity.CRITICAL if attack_type != AttackType.UNKNOWN else Severity.HIGH,
                raw=obj
            )
