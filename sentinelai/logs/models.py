from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class Event:
    ts: datetime
    source: str            # "ssh" | "web"
    ip: str
    action: str            # ssh: failed|accepted|invalid_user ; web: request
    user: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    size: int = 0
    user_agent: str = ""


@dataclass
class Finding:
    rule: str
    severity: str
    ip: str
    title: str
    description: str
    technique: str | None = None
    count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["first_seen"] = self.first_seen.isoformat() if self.first_seen else None
        d["last_seen"] = self.last_seen.isoformat() if self.last_seen else None
        return d
