from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any

from securecoda.config import load_settings
from securecoda.scanner import Scanner
from securecoda.store import AlertStore


class FakeCodaClient:
    def list_docs(self, workspace_id: str | None = None) -> list[dict[str, Any]]:
        return [
            {
                "id": "doc_1",
                "name": "Finance Runbook",
                "updatedAt": "2024-01-01T00:00:00Z",
                "isPublished": True,
                "browserLink": "https://coda.io/d/doc_1",
            }
        ]

    def list_permissions(self, doc_id: str) -> list[dict[str, Any]]:
        return [
            {
                "id": "perm_1",
                "principal": {"type": "user", "email": "vendor@example.net"},
            }
        ]

    def list_tables(self, doc_id: str) -> list[dict[str, Any]]:
        return [{"id": "grid_1", "name": "Secrets", "browserLink": "https://coda.io/d/doc_1#grid_1"}]

    def list_rows(self, doc_id: str, table_id: str, max_rows: int) -> list[dict[str, Any]]:
        return [
            {
                "id": "row_1",
                "name": "prod",
                "browserLink": "https://coda.io/d/doc_1#row_1",
                "values": {"Service": "billing", "password": "secret12345"},
            }
        ]

    def list_pages(self, doc_id: str) -> list[dict[str, Any]]:
        return [{"id": "page_1", "name": "Ops", "browserLink": "https://coda.io/d/doc_1/page_1"}]

    def export_page_content(self, doc_id: str, page_id: str, output_format: str = "markdown") -> str:
        return "Temporary card: 4111 1111 1111 1111"


class ScannerTests(unittest.TestCase):
    def test_scanner_creates_alerts_across_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = replace(
                load_settings(),
                internal_domains=["example.com"],
                unused_after_days=30,
                sqlite_path=Path(tmp) / "securecoda.db",
                scan_pages=True,
            )
            store = AlertStore(settings.sqlite_path)
            scanner = Scanner(FakeCodaClient(), store, settings)

            result = scanner.scan()
            rules = {alert["rule"] for alert in store.list_alerts("open")}

            self.assertEqual(result.status, "completed")
            self.assertIn("doc.unused", rules)
            self.assertIn("sharing.published", rules)
            self.assertIn("sharing.external_user", rules)
            self.assertIn("sensitive.password", rules)
            self.assertIn("sensitive.credit_card", rules)


if __name__ == "__main__":
    unittest.main()

