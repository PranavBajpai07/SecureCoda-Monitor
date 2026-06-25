from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Alert:
    id: str
    fingerprint: str
    rule: str
    severity: str
    status: str
    doc_id: str
    doc_name: str
    object_type: str
    object_id: str
    object_name: str
    location: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    remediation: dict[str, Any] = field(default_factory=dict)
    first_seen: str = field(default_factory=utc_now)
    last_seen: str = field(default_factory=utc_now)
    browser_link: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Detection:
    rule: str
    severity: str
    label: str
    excerpt: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScanResult:
    scan_id: str
    started_at: str
    finished_at: str
    status: str
    docs_scanned: int
    alerts_found: int
    errors: list[str]

