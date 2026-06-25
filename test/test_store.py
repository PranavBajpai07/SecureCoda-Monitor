from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from securecoda.models import Alert, ScanResult, utc_now
from securecoda.store import AlertStore


class StoreTests(unittest.TestCase):
    def test_alerts_are_upserted_and_stale_alerts_resolve(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AlertStore(Path(tmp) / "securecoda.db")
            alert = Alert(
                id="al_1",
                fingerprint="fp_1",
                rule="sharing.published",
                severity="high",
                status="open",
                doc_id="doc_1",
                doc_name="Roadmap",
                object_type="doc",
                object_id="doc_1",
                object_name="Roadmap",
                location="https://coda.io/d/doc_1",
                summary="Published doc",
                details={},
                remediation={"action": "unpublish_doc"},
            )

            self.assertTrue(store.upsert_alert(alert))
            self.assertFalse(store.upsert_alert(alert))
            self.assertEqual(len(store.list_alerts("open")), 1)

            scan = ScanResult("scan_1", utc_now(), utc_now(), "completed", 1, 0, [])
            store.start_scan(scan.scan_id, scan.started_at)
            store.finish_scan(scan, set())

            self.assertEqual(len(store.list_alerts("open")), 0)
            self.assertEqual(len(store.list_alerts("resolved")), 1)


if __name__ == "__main__":
    unittest.main()

