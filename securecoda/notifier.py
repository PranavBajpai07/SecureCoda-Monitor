from __future__ import annotations

import json
import logging
from typing import Any
from urllib.request import Request, urlopen


logger = logging.getLogger(__name__)


class SlackNotifier:
    def __init__(self, webhook_url: str | None) -> None:
        self.webhook_url = webhook_url

    def enabled(self) -> bool:
        return bool(self.webhook_url)

    def send_alert_summary(self, alerts: list[dict[str, Any]]) -> None:
        if not self.webhook_url or not alerts:
            return
        critical = sum(1 for alert in alerts if alert.get("severity") == "critical")
        high = sum(1 for alert in alerts if alert.get("severity") == "high")
        payload = {
            "text": (
                f"SecureCoda detected {len(alerts)} new alert(s): "
                f"{critical} critical, {high} high."
            )
        }
        request = Request(
            self.webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=10):
                logger.info("Sent Slack alert summary")
        except Exception:
            logger.exception("Failed to send Slack alert summary")

