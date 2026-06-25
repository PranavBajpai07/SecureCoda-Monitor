from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from .coda_client import CodaClient
from .config import Settings
from .store import AlertStore


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RemediationResult:
    status: str
    message: str
    response: dict[str, Any]


class Remediator:
    def __init__(self, client: CodaClient | None, store: AlertStore, settings: Settings) -> None:
        self.client = client
        self.store = store
        self.settings = settings

    def remediate(self, alert_id: str) -> RemediationResult:
        alert = self.store.get_alert(alert_id)
        if not alert:
            return RemediationResult("error", "Alert not found.", {})
        if not self.client:
            return RemediationResult("error", "CODA_API_TOKEN is not configured.", {})

        remediation = alert.get("remediation") or {}
        action = remediation.get("action")
        if not action:
            return RemediationResult("error", "No remediation action is registered for this alert.", {})

        if self.settings.remediation_dry_run:
            message = f"Dry run: would execute {action}."
            self.store.record_audit(action, "dry_run", message, alert_id, remediation)
            return RemediationResult("dry_run", message, remediation)

        destructive_actions = {"delete_doc", "delete_row", "delete_page_content"}
        if action in destructive_actions and not self.settings.destructive_remediation_enabled:
            message = (
                f"{action} is destructive. Set DESTRUCTIVE_REMEDIATION_ENABLED=true "
                "to allow this action."
            )
            self.store.record_audit(action, "blocked", message, alert_id, remediation)
            return RemediationResult("blocked", message, remediation)

        try:
            response = self._execute(alert, remediation)
            message = f"Executed {action}."
            self.store.update_alert_status(alert_id, "remediated", message)
            self.store.record_audit(action, "success", message, alert_id, response)
            logger.info("Remediated alert %s with %s", alert_id, action)
            return RemediationResult("success", message, response)
        except Exception as exc:
            logger.exception("Failed to remediate alert %s", alert_id)
            message = str(exc)
            self.store.record_audit(action, "error", message, alert_id, remediation)
            return RemediationResult("error", message, {})

    def _execute(self, alert: dict[str, Any], remediation: dict[str, Any]) -> dict[str, Any]:
        assert self.client is not None
        action = remediation["action"]
        doc_id = alert["doc_id"]

        if action == "unpublish_doc":
            response = self.client.unpublish_doc(doc_id)
            if remediation.get("lock_acl_after"):
                acl = self.client.update_acl_settings(
                    doc_id,
                    {
                        "allowEditorsToChangePermissions": False,
                        "allowViewersToRequestEditing": False,
                    },
                )
                return {"unpublish": response, "acl": acl}
            return response

        if action == "remove_permission":
            permission_id = remediation["permission_id"]
            response = self.client.delete_permission(doc_id, permission_id)
            if remediation.get("lock_acl_after"):
                acl = self.client.update_acl_settings(
                    doc_id,
                    {
                        "allowEditorsToChangePermissions": False,
                        "allowViewersToRequestEditing": False,
                    },
                )
                return {"deletePermission": response, "acl": acl}
            return response

        if action == "delete_row":
            return self.client.delete_row(doc_id, remediation["table_id"], remediation["row_id"])

        if action == "delete_page_content":
            return self.client.delete_page_content(doc_id, remediation["page_id"])

        if action == "delete_doc":
            return self.client.delete_doc(doc_id)

        if action == "lock_acl":
            return self.client.update_acl_settings(
                doc_id,
                {
                    "allowEditorsToChangePermissions": False,
                    "allowViewersToRequestEditing": False,
                },
            )

        raise ValueError(f"Unsupported remediation action: {action}")

