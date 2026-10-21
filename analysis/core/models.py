from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AttackType(str, Enum):
    DDOS = "ddos"
    SQLI = "sqli"
    XSS = "xss"
    SCAN = "scan"
    UNKNOWN = "unknown"

@dataclass
class SecurityEvent:
    timestamp: datetime
    source_ip: str
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    attack_type: AttackType = AttackType.UNKNOWN
    signature: str = ""
    severity: Severity = Severity.LOW
    raw: dict = field(default_factory=dict)
