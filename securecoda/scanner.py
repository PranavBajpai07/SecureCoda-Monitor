from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .coda_client import CodaClient
from .config import Settings
from .detectors import scan_row_values, scan_text
from .models import Alert, Detection, ScanResult, utc_now
from .notifier import SlackNotifier
from .store import AlertStore


logger = logging.getLogger(__name__)


class Scanner:
    def __init__(
        self,
        client: CodaClient | None,
        store: AlertStore,
        settings: Settings,
        notifier: SlackNotifier | None = None,
    ) -> None:
        self.client = client
        self.store = store
        self.settings = settings
        self.notifier = notifier or SlackNotifier(None)

    def scan(self) -> ScanResult:
        scan_id = uuid.uuid4().hex
        started_at = utc_now()
        self.store.start_scan(scan_id, started_at)

        errors: list[str] = []
        active_fingerprints: set[str] = set()
        created_alerts: list[dict[str, Any]] = []
        docs_scanned = 0

        if not self.client:
            error = "CODA_API_TOKEN is not configured."
            result = ScanResult(scan_id, started_at, utc_now(), "error", 0, 0, [error])
            self.store.finish_scan(result, set())
            self.store.record_audit("scan", "error", error)
            return result

        try:
            docs = self.client.list_docs(self.settings.workspace_id)
        except Exception as exc:
            logger.exception("Failed to list Coda docs")
            result = ScanResult(scan_id, started_at, utc_now(), "error", 0, 0, [str(exc)])
            self.store.finish_scan(result, set())
            return result

        for doc in docs:
            docs_scanned += 1
            try:
                alerts = self._scan_doc(doc)
                for alert in alerts:
                    active_fingerprints.add(alert.fingerprint)
                    created = self.store.upsert_alert(alert)
                    if created:
                        created_alerts.append(alert.to_dict())
            except Exception as exc:
                message = f"{doc.get('name', doc.get('id'))}: {exc}"
                logger.exception("Failed to scan doc %s", doc.get("id"))
                errors.append(message)

        status = "completed_with_errors" if errors else "completed"
        result = ScanResult(scan_id, started_at, utc_now(), status, docs_scanned, len(active_fingerprints), errors)
        self.store.finish_scan(result, active_fingerprints)
        self.notifier.send_alert_summary(created_alerts)
        return result

    def _scan_doc(self, doc: dict[str, Any]) -> list[Alert]:
        alerts: list[Alert] = []
        alerts.extend(self._detect_unused_doc(doc))
        alerts.extend(self._detect_published_doc(doc))
        alerts.extend(self._detect_permissions(doc))
        alerts.extend(self._detect_table_data(doc))
        if self.settings.scan_pages:
            alerts.extend(self._detect_page_content(doc))
        return alerts

    def _detect_unused_doc(self, doc: dict[str, Any]) -> list[Alert]:
        updated_at = _parse_coda_time(doc.get("updatedAt") or doc.get("createdAt"))
        if not updated_at:
            return []

        age = datetime.now(timezone.utc) - updated_at
        if age < timedelta(days=self.settings.unused_after_days):
            return []

        days = int(age.total_seconds() // 86400)
        return [
            self._alert(
                doc=doc,
                rule="doc.unused",
                severity="medium",
                object_type="doc",
                object_id=doc["id"],
                object_name=doc.get("name", "Untitled doc"),
                location=doc.get("browserLink", ""),
                summary=f"Document has not been modified for {days} days.",
                details={"updatedAt": doc.get("updatedAt"), "ageDays": days},
                remediation={"action": "delete_doc"},
                browser_link=doc.get("browserLink"),
            )
        ]

    def _detect_published_doc(self, doc: dict[str, Any]) -> list[Alert]:
        if not _is_published(doc):
            return []
        return [
            self._alert(
                doc=doc,
                rule="sharing.published",
                severity="high",
                object_type="doc",
                object_id=doc["id"],
                object_name=doc.get("name", "Untitled doc"),
                location=doc.get("browserLink", ""),
                summary="Document is published and may be publicly accessible.",
                details={"published": doc.get("published") or doc.get("isPublished")},
                remediation={"action": "unpublish_doc", "lock_acl_after": True},
                browser_link=doc.get("browserLink"),
            )
        ]

    def _detect_permissions(self, doc: dict[str, Any]) -> list[Alert]:
        alerts: list[Alert] = []
        try:
            permissions = self.client.list_permissions(doc["id"]) if self.client else []
        except Exception as exc:
            logger.warning("Could not read permissions for doc %s: %s", doc.get("id"), exc)
            return alerts

        for permission in permissions:
            principal = permission.get("principal") or permission.get("recipient") or {}
            principal_type = str(principal.get("type") or permission.get("type") or "").lower()
            email = str(principal.get("email") or permission.get("email") or "").lower()
            permission_id = permission.get("id")

            if principal_type in {"anyone", "anonymous", "public", "anyonewithlink"}:
                alerts.append(
                    self._alert(
                        doc=doc,
                        rule="sharing.public_link",
                        severity="critical",
                        object_type="permission",
                        object_id=permission_id or "public",
                        object_name="Public link",
                        location=doc.get("browserLink", ""),
                        summary="Document has a public or anyone-with-link permission.",
                        details={"permission": permission},
                        remediation={"action": "remove_permission", "permission_id": permission_id, "lock_acl_after": True}
                        if permission_id
                        else {"action": "lock_acl"},
                        browser_link=doc.get("browserLink"),
                    )
                )
                continue

            if email and self.settings.internal_domains and _domain(email) not in self.settings.internal_domains:
                alerts.append(
                    self._alert(
                        doc=doc,
                        rule="sharing.external_user",
                        severity="high",
                        object_type="permission",
                        object_id=permission_id or email,
                        object_name=email,
                        location=doc.get("browserLink", ""),
                        summary=f"Document is shared with external account {email}.",
                        details={"permission": permission, "domain": _domain(email)},
                        remediation={"action": "remove_permission", "permission_id": permission_id, "lock_acl_after": True}
                        if permission_id
                        else {"action": "lock_acl"},
                        browser_link=doc.get("browserLink"),
                    )
                )

        return alerts

    def _detect_table_data(self, doc: dict[str, Any]) -> list[Alert]:
        alerts: list[Alert] = []
        tables = self.client.list_tables(doc["id"]) if self.client else []
        for table in tables:
            table_id = table["id"]
            rows = self.client.list_rows(doc["id"], table_id, self.settings.max_rows_per_table) if self.client else []
            for row in rows:
                values = row.get("values") or {}
                for detection in scan_row_values(values):
                    alerts.append(
                        self._detection_alert(
                            doc=doc,
                            detection=detection,
                            object_type="row",
                            object_id=row.get("id", ""),
                            object_name=row.get("name") or table.get("name", "Row"),
                            location=f"{table.get('name', table_id)} / {row.get('name', row.get('id', 'row'))}",
                            details={
                                **detection.details,
                                "tableId": table_id,
                                "tableName": table.get("name"),
                                "rowId": row.get("id"),
                                "rowName": row.get("name"),
                            },
                            remediation={"action": "delete_row", "table_id": table_id, "row_id": row.get("id")},
                            browser_link=row.get("browserLink") or table.get("browserLink") or doc.get("browserLink"),
                        )
                    )
        return alerts

    def _detect_page_content(self, doc: dict[str, Any]) -> list[Alert]:
        alerts: list[Alert] = []
        pages = self.client.list_pages(doc["id"]) if self.client else []
        for page in pages:
            page_id = page["id"]
            try:
                content = self.client.export_page_content(
                    doc["id"],
                    page_id,
                    self.settings.page_export_format,
                ) if self.client else ""
            except Exception as exc:
                logger.warning("Could not export page %s in doc %s: %s", page_id, doc.get("id"), exc)
                continue

            for detection in scan_text(content):
                alerts.append(
                    self._detection_alert(
                        doc=doc,
                        detection=detection,
                        object_type="page",
                        object_id=page_id,
                        object_name=page.get("name", "Untitled page"),
                        location=page.get("name", page_id),
                        details={**detection.details, "pageId": page_id, "pageName": page.get("name")},
                        remediation={"action": "delete_page_content", "page_id": page_id},
                        browser_link=page.get("browserLink") or doc.get("browserLink"),
                    )
                )
        return alerts

    def _detection_alert(
        self,
        doc: dict[str, Any],
        detection: Detection,
        object_type: str,
        object_id: str,
        object_name: str,
        location: str,
        details: dict[str, Any],
        remediation: dict[str, Any],
        browser_link: str | None,
    ) -> Alert:
        return self._alert(
            doc=doc,
            rule=detection.rule,
            severity=detection.severity,
            object_type=object_type,
            object_id=object_id,
            object_name=object_name,
            location=location,
            summary=f"{detection.label}: {detection.excerpt}",
            details={"label": detection.label, "excerpt": detection.excerpt, **details},
            remediation=remediation,
            browser_link=browser_link,
        )

    def _alert(
        self,
        doc: dict[str, Any],
        rule: str,
        severity: str,
        object_type: str,
        object_id: str,
        object_name: str,
        location: str,
        summary: str,
        details: dict[str, Any],
        remediation: dict[str, Any],
        browser_link: str | None = None,
    ) -> Alert:
        fingerprint = _fingerprint(rule, doc["id"], object_type, object_id, summary[:160])
        return Alert(
            id=_alert_id(fingerprint),
            fingerprint=fingerprint,
            rule=rule,
            severity=severity,
            status="open",
            doc_id=doc["id"],
            doc_name=doc.get("name", "Untitled doc"),
            object_type=object_type,
            object_id=object_id,
            object_name=object_name,
            location=location,
            summary=summary,
            details=details,
            remediation=remediation,
            browser_link=browser_link,
        )


def _fingerprint(*parts: str) -> str:
    normalized = "|".join(str(part) for part in parts)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _alert_id(fingerprint: str) -> str:
    return f"al_{fingerprint[:16]}"


def _parse_coda_time(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_published(doc: dict[str, Any]) -> bool:
    if doc.get("isPublished") is True:
        return True
    published = doc.get("published")
    return bool(published and published not in {"false", "False"})


def _domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower() if "@" in email else ""

