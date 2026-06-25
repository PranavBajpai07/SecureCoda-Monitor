from __future__ import annotations

import unittest

from securecoda.detectors import scan_row_values, scan_text


class DetectorTests(unittest.TestCase):
    def test_detects_and_masks_password_assignments(self) -> None:
        detections = scan_text("db_password = superSecret123")

        self.assertTrue(any(d.rule == "sensitive.password" for d in detections))
        self.assertNotIn("superSecret123", detections[0].excerpt)

    def test_detects_luhn_valid_credit_card(self) -> None:
        detections = scan_text("test card 4111 1111 1111 1111")

        self.assertTrue(any(d.rule == "sensitive.credit_card" for d in detections))

    def test_ignores_non_luhn_number_sequences(self) -> None:
        detections = scan_text("tracking number 4111 1111 1111 1112")

        self.assertFalse(any(d.rule == "sensitive.credit_card" for d in detections))

    def test_sensitive_column_names_are_flagged(self) -> None:
        detections = scan_row_values({"Customer": "Ada", "API Token": "abc123456789"})

        self.assertTrue(any(d.rule == "sensitive.column_name" for d in detections))


if __name__ == "__main__":
    unittest.main()

