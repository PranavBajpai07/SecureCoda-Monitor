from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from .models import Detection


@dataclass(frozen=True)
class SensitivePattern:
    rule: str
    label: str
    severity: str
    regex: re.Pattern[str]


PATTERNS: tuple[SensitivePattern, ...] = (
    SensitivePattern(
        "sensitive.password",
        "Password or secret assignment",
        "critical",
        re.compile(
            r"(?i)(?:\b|_)(password|passwd|pwd|secret|api[_ -]?key|token|private[_ -]?key)\b"
            r"\s*[:=]\s*[\"']?([^\s\"']{6,})"
        ),
    ),
    SensitivePattern(
        "sensitive.aws_key",
        "AWS access key",
        "critical",
        re.compile(r"\b(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    SensitivePattern(
        "sensitive.private_key",
        "Private key material",
        "critical",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----"),
    ),
    SensitivePattern(
        "sensitive.ssn",
        "US Social Security number",
        "high",
        re.compile(r"\b(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"),
    ),
    SensitivePattern(
        "sensitive.iban",
        "IBAN-like account number",
        "high",
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    ),
)

CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
SENSITIVE_COLUMN_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_ -]?key|ssn|salary|bank|iban|card|pan)\b"
)


def flatten_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(value)


def flatten_values(values: dict[str, Any]) -> str:
    parts: list[str] = []
    for key, value in values.items():
        text = flatten_value(value)
        if text:
            parts.append(f"{key}: {text}")
    return "\n".join(parts)


def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:3]}...{value[-2:]}"


def make_excerpt(text: str, start: int, end: int, width: int = 90) -> str:
    low = max(0, start - width // 2)
    high = min(len(text), end + width // 2)
    excerpt = text[low:high].replace("\n", " ").strip()
    if low > 0:
        excerpt = "..." + excerpt
    if high < len(text):
        excerpt += "..."
    return excerpt


def _luhn_checksum(number: str) -> bool:
    digits = [int(char) for char in number if char.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def scan_text(text: str) -> list[Detection]:
    detections: list[Detection] = []
    if not text:
        return detections

    for pattern in PATTERNS:
        for match in pattern.regex.finditer(text):
            raw = match.group(0)
            if pattern.rule == "sensitive.password" and len(match.groups()) >= 2:
                raw = raw.replace(match.group(2), mask_secret(match.group(2)))
            detections.append(
                Detection(
                    rule=pattern.rule,
                    severity=pattern.severity,
                    label=pattern.label,
                    excerpt=make_excerpt(text, match.start(), match.end()).replace(match.group(0), raw),
                    details={"matched": pattern.label},
                )
            )

    for match in CREDIT_CARD_PATTERN.finditer(text):
        candidate = re.sub(r"\D", "", match.group(0))
        if _luhn_checksum(candidate):
            detections.append(
                Detection(
                    rule="sensitive.credit_card",
                    severity="critical",
                    label="Credit card number",
                    excerpt=make_excerpt(text, match.start(), match.end()).replace(
                        match.group(0), mask_secret(candidate)
                    ),
                    details={"matched": "Luhn-valid payment card number"},
                )
            )

    return detections


def scan_row_values(values: dict[str, Any]) -> list[Detection]:
    detections = scan_text(flatten_values(values))
    for column, value in values.items():
        text_value = flatten_value(value)
        if text_value and SENSITIVE_COLUMN_PATTERN.search(str(column)):
            detections.append(
                Detection(
                    rule="sensitive.column_name",
                    severity="medium",
                    label="Sensitive column name with populated value",
                    excerpt=f"{column}: {mask_secret(text_value)}",
                    details={"column": column},
                )
            )
    return _dedupe(detections)


def _dedupe(detections: Iterable[Detection]) -> list[Detection]:
    seen: set[tuple[str, str]] = set()
    unique: list[Detection] = []
    for detection in detections:
        key = (detection.rule, detection.excerpt)
        if key in seen:
            continue
        seen.add(key)
        unique.append(detection)
    return unique


