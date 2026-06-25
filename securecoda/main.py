from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .coda_client import CodaClient
from .config import load_settings
from .logging_config import configure_logging
from .notifier import SlackNotifier
from .remediation import Remediator
from .scanner import Scanner
from .scheduler import Poller
from .store import AlertStore


settings = load_settings()
configure_logging(settings.log_file)
logger = logging.getLogger(__name__)

store = AlertStore(settings.sqlite_path)
client = CodaClient(settings.coda_api_token, settings.coda_base_url) if settings.coda_api_token else None
notifier = SlackNotifier(settings.slack_webhook_url)
scanner = Scanner(client, store, settings, notifier)
remediator = Remediator(client, store, settings)
poller = Poller(scanner, settings.poll_interval_seconds)

app = FastAPI(title="SecureCoda", version="1.0.0")
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.on_event("startup")
def startup() -> None:
    poller.start()
    if settings.scan_on_startup:
        threading.Thread(target=poller.trigger_once, name="securecoda-startup-scan", daemon=True).start()


@app.on_event("shutdown")
def shutdown() -> None:
    poller.stop()


@app.get("/")
def dashboard() -> FileResponse:
    return FileResponse(static_dir / "index.html")


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "tokenConfigured": settings.token_configured,
        "dryRun": settings.remediation_dry_run,
        "destructiveRemediationEnabled": settings.destructive_remediation_enabled,
        "pollIntervalSeconds": settings.poll_interval_seconds,
        "latestScan": store.latest_scan(),
    }


@app.get("/api/alerts")
def alerts(status: str | None = Query(default="open")) -> dict[str, Any]:
    normalized_status = None if status in {"", "all", None} else status
    return {
        "summary": store.summary(),
        "latestScan": store.latest_scan(),
        "items": store.list_alerts(normalized_status),
    }


@app.post("/api/scans")
def trigger_scan(background_tasks: BackgroundTasks) -> dict[str, str]:
    background_tasks.add_task(poller.trigger_once)
    return {"status": "queued"}


@app.post("/api/alerts/{alert_id}/remediate")
def remediate(alert_id: str) -> dict[str, Any]:
    alert = store.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    result = remediator.remediate(alert_id)
    http_status = 200 if result.status in {"success", "dry_run", "blocked"} else 500
    if http_status >= 400:
        raise HTTPException(status_code=http_status, detail=result.message)
    return {"status": result.status, "message": result.message, "response": result.response}

