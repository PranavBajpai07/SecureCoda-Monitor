from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .models import Alert, ScanResult, utc_now


class AlertStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                create table if not exists alerts (
                    id text primary key,
                    fingerprint text not null unique,
                    rule text not null,
                    severity text not null,
                    status text not null,
                    doc_id text not null,
                    doc_name text not null,
                    object_type text not null,
                    object_id text not null,
                    object_name text not null,
                    location text not null,
                    summary text not null,
                    details_json text not null,
                    remediation_json text not null,
                    first_seen text not null,
                    last_seen text not null,
                    resolved_at text,
                    remediation_message text,
                    browser_link text
                );
                create index if not exists idx_alerts_status on alerts(status);
                create index if not exists idx_alerts_rule on alerts(rule);

                create table if not exists scan_runs (
                    id text primary key,
                    started_at text not null,
                    finished_at text,
                    status text not null,
                    docs_scanned integer not null default 0,
                    alerts_found integer not null default 0,
                    errors_json text not null default '[]'
                );

                create table if not exists audit_log (
                    id integer primary key autoincrement,
                    created_at text not null,
                    alert_id text,
                    action text not null,
                    status text not null,
                    message text not null,
                    payload_json text not null
                );
                """
            )

    def start_scan(self, scan_id: str, started_at: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                insert into scan_runs (id, started_at, status, errors_json)
                values (?, ?, 'running', '[]')
                """,
                (scan_id, started_at),
            )

    def finish_scan(self, result: ScanResult, active_fingerprints: set[str]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                update scan_runs
                set finished_at = ?, status = ?, docs_scanned = ?, alerts_found = ?, errors_json = ?
                where id = ?
                """,
                (
                    result.finished_at,
                    result.status,
                    result.docs_scanned,
                    result.alerts_found,
                    json.dumps(result.errors),
                    result.scan_id,
                ),
            )
            if active_fingerprints:
                placeholders = ",".join("?" for _ in active_fingerprints)
                conn.execute(
                    f"""
                    update alerts
                    set status = 'resolved', resolved_at = ?
                    where status = 'open' and fingerprint not in ({placeholders})
                    """,
                    (result.finished_at, *active_fingerprints),
                )
            else:
                conn.execute(
                    """
                    update alerts
                    set status = 'resolved', resolved_at = ?
                    where status = 'open'
                    """,
                    (result.finished_at,),
                )

    def upsert_alert(self, alert: Alert) -> bool:
        now = utc_now()
        with self._connect() as conn:
            existing = conn.execute(
                "select id, status, first_seen from alerts where fingerprint = ?",
                (alert.fingerprint,),
            ).fetchone()
            if existing:
                conn.execute(
                    """
                    update alerts
                    set rule = ?, severity = ?, status = 'open', doc_id = ?, doc_name = ?,
                        object_type = ?, object_id = ?, object_name = ?, location = ?,
                        summary = ?, details_json = ?, remediation_json = ?, last_seen = ?,
                        resolved_at = null, browser_link = ?
                    where fingerprint = ?
                    """,
                    (
                        alert.rule,
                        alert.severity,
                        alert.doc_id,
                        alert.doc_name,
                        alert.object_type,
                        alert.object_id,
                        alert.object_name,
                        alert.location,
                        alert.summary,
                        json.dumps(alert.details),
                        json.dumps(alert.remediation),
                        now,
                        alert.browser_link,
                        alert.fingerprint,
                    ),
                )
                return False

            conn.execute(
                """
                insert into alerts (
                    id, fingerprint, rule, severity, status, doc_id, doc_name, object_type,
                    object_id, object_name, location, summary, details_json, remediation_json,
                    first_seen, last_seen, browser_link
                )
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.id,
                    alert.fingerprint,
                    alert.rule,
                    alert.severity,
                    alert.status,
                    alert.doc_id,
                    alert.doc_name,
                    alert.object_type,
                    alert.object_id,
                    alert.object_name,
                    alert.location,
                    alert.summary,
                    json.dumps(alert.details),
                    json.dumps(alert.remediation),
                    alert.first_seen,
                    alert.last_seen,
                    alert.browser_link,
                ),
            )
            return True

    def list_alerts(self, status: str | None = "open") -> list[dict[str, Any]]:
        query = "select * from alerts"
        params: tuple[Any, ...] = ()
        if status:
            query += " where status = ?"
            params = (status,)
        query += """
            order by
                case severity
                    when 'critical' then 1
                    when 'high' then 2
                    when 'medium' then 3
                    else 4
                end,
                last_seen desc
        """
        with self._connect() as conn:
            return [self._row_to_alert(row) for row in conn.execute(query, params)]

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("select * from alerts where id = ?", (alert_id,)).fetchone()
            return self._row_to_alert(row) if row else None

    def update_alert_status(self, alert_id: str, status: str, message: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                update alerts
                set status = ?, remediation_message = ?, resolved_at = ?
                where id = ?
                """,
                (status, message, utc_now(), alert_id),
            )

    def record_audit(
        self,
        action: str,
        status: str,
        message: str,
        alert_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                insert into audit_log (created_at, alert_id, action, status, message, payload_json)
                values (?, ?, ?, ?, ?, ?)
                """,
                (utc_now(), alert_id, action, status, message, json.dumps(payload or {})),
            )

    def latest_scan(self) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "select * from scan_runs order by started_at desc limit 1"
            ).fetchone()
            if not row:
                return None
            data = dict(row)
            data["errors"] = json.loads(data.pop("errors_json") or "[]")
            return data

    def summary(self) -> dict[str, Any]:
        with self._connect() as conn:
            total_open = conn.execute("select count(*) from alerts where status = 'open'").fetchone()[0]
            by_severity = {
                row["severity"]: row["count"]
                for row in conn.execute(
                    "select severity, count(*) as count from alerts where status = 'open' group by severity"
                )
            }
            by_rule = {
                row["rule"]: row["count"]
                for row in conn.execute(
                    "select rule, count(*) as count from alerts where status = 'open' group by rule"
                )
            }
        return {"open": total_open, "bySeverity": by_severity, "byRule": by_rule}

    def _row_to_alert(self, row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["details"] = json.loads(data.pop("details_json") or "{}")
        data["remediation"] = json.loads(data.pop("remediation_json") or "{}")
        return data


