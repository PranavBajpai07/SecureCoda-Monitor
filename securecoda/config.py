from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return int(value)


def _list(name: str) -> list[str]:
    value = os.getenv(name, "")
    return [item.strip().lower() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    coda_api_token: str | None
    coda_base_url: str
    workspace_id: str | None
    internal_domains: list[str]
    unused_after_days: int
    poll_interval_seconds: int
    scan_on_startup: bool
    remediation_dry_run: bool
    destructive_remediation_enabled: bool
    scan_pages: bool
    page_export_format: str
    max_rows_per_table: int
    sqlite_path: Path
    log_file: Path
    slack_webhook_url: str | None

    @property
    def token_configured(self) -> bool:
        return bool(self.coda_api_token)


def load_settings() -> Settings:
    return Settings(
        coda_api_token=os.getenv("CODA_API_TOKEN"),
        coda_base_url=os.getenv("CODA_BASE_URL", "https://coda.io/apis/v1").rstrip("/"),
        workspace_id=os.getenv("CODA_WORKSPACE_ID") or None,
        internal_domains=_list("CODA_INTERNAL_DOMAINS"),
        unused_after_days=_int("UNUSED_AFTER_DAYS", 90),
        poll_interval_seconds=_int("POLL_INTERVAL_SECONDS", 3600),
        scan_on_startup=_bool("SCAN_ON_STARTUP", True),
        remediation_dry_run=_bool("REMEDIATION_DRY_RUN", True),
        destructive_remediation_enabled=_bool("DESTRUCTIVE_REMEDIATION_ENABLED", False),
        scan_pages=_bool("SCAN_PAGES", True),
        page_export_format=os.getenv("PAGE_EXPORT_FORMAT", "markdown"),
        max_rows_per_table=_int("MAX_ROWS_PER_TABLE", 500),
        sqlite_path=Path(os.getenv("SQLITE_PATH", "data/securecoda.db")),
        log_file=Path(os.getenv("LOG_FILE", "logs/securecoda.log")),
        slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL") or None,
    )

