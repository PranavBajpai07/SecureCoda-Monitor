# SecureCoda: Activity & Exposure Monitor

SecureCoda is a standalone FastAPI service that monitors Coda docs for stale activity, risky sharing, and sensitive content in tables and pages. It stores findings in SQLite, writes operational logs to disk, and serves a dashboard with auto-refresh, scan triggering, alert details, and remediation actions.

The implementation uses Coda's REST API base path `https://coda.io/apis/v1`, bearer-token authentication, list endpoints with pagination, page content export, table row reads, permission deletion, doc unpublishing, row deletion, and page-content deletion.

## Features

- Lists Coda docs and evaluates `createdAt`, `updatedAt`, publishing, permissions, tables, rows, and pages.
- Flags docs that have not been modified after the configured threshold.
- Detects published docs, public link permissions, and shares to domains outside `CODA_INTERNAL_DOMAINS`.
- Scans table rows and exported page content for passwords/secrets, API keys, private keys, SSNs, IBAN-like values, and Luhn-valid card numbers.
- Stores open, resolved, and remediated alerts in SQLite with an audit log.
- Provides dashboard remediation buttons backed by Coda API calls.
- Supports dry-run remediation by default, with explicit opt-in for destructive actions.
- Optionally posts a Slack webhook summary when new alerts are created.

## Architecture

```text
securecoda/
  coda_client.py     Coda REST client, pagination, retries for 429s, export downloads
  detectors.py       Sensitive-pattern rules and row/content scanning
  scanner.py         Orchestrates document, permission, table, and page checks
  remediation.py     Maps alert actions to Coda API mutations
  store.py           SQLite alert, scan-run, and audit-log persistence
  scheduler.py       Background polling loop
  main.py            FastAPI routes and dashboard serving
  static/            HTML/CSS/JS dashboard
```

The poller runs inside the FastAPI process. For larger tenants, the scanner and store boundaries are intentionally separate so the poller can be moved to a worker process or queue without rewriting the detection rules.

## Setup

1. Create a Coda API token from your Coda account settings.
2. Copy `.env.example` to `.env` and set at least:

```bash
CODA_API_TOKEN=your-token
CODA_INTERNAL_DOMAINS=yourcompany.com
```

3. Install dependencies and run locally:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn securecoda.main:app --reload --env-file .env
```

4. Open `http://localhost:8000`.

## Docker

```bash
docker build -t securecoda .
docker run --env-file .env -p 8000:8000 -v securecoda-data:/app/data -v securecoda-logs:/app/logs securecoda
```

The app listens on port `8000`.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `CODA_API_TOKEN` | unset | Bearer token for the Coda API. |
| `CODA_WORKSPACE_ID` | unset | Optional workspace filter for docs. |
| `CODA_INTERNAL_DOMAINS` | unset | Comma-separated domains considered internal. |
| `UNUSED_AFTER_DAYS` | `90` | Age threshold for stale docs. |
| `POLL_INTERVAL_SECONDS` | `3600` | Background scan interval. |
| `SCAN_ON_STARTUP` | `true` | Run a scan when the app starts. |
| `SCAN_PAGES` | `true` | Export and scan page content. |
| `PAGE_EXPORT_FORMAT` | `markdown` | Coda page export output format. |
| `MAX_ROWS_PER_TABLE` | `500` | Row scan cap per table. |
| `REMEDIATION_DRY_RUN` | `true` | Log remediation intent without mutating Coda. |
| `DESTRUCTIVE_REMEDIATION_ENABLED` | `false` | Allows doc, row, and page-content deletion. |
| `SQLITE_PATH` | `data/securecoda.db` | SQLite database path. |
| `LOG_FILE` | `logs/securecoda.log` | Rotating application log path. |
| `SLACK_WEBHOOK_URL` | unset | Optional webhook for new-alert summaries. |

## Detection Rules

- `doc.unused`: `updatedAt` or `createdAt` is older than `UNUSED_AFTER_DAYS`.
- `sharing.published`: doc metadata indicates that the doc is published.
- `sharing.public_link`: doc permissions include an anyone/public-style principal.
- `sharing.external_user`: doc permissions include an email domain outside `CODA_INTERNAL_DOMAINS`.
- `sensitive.password`: password, secret, token, API key, or private-key assignment patterns.
- `sensitive.aws_key`: AWS access key patterns.
- `sensitive.private_key`: PEM private key markers.
- `sensitive.ssn`: US SSN-like values with basic invalid-prefix filtering.
- `sensitive.iban`: IBAN-like account identifiers.
- `sensitive.credit_card`: Luhn-valid payment card candidates.
- `sensitive.column_name`: populated table columns whose names imply sensitive values.

## Remediation Actions

The dashboard's **Fix** button calls `POST /api/alerts/{alert_id}/remediate`.

- Published docs: unpublish the doc and tighten ACL settings.
- Public or external sharing: remove the permission and tighten ACL settings.
- Sensitive table rows: delete the row.
- Sensitive page content: delete page content.
- Unused docs: delete the doc.

`REMEDIATION_DRY_RUN=true` is the default. Set it to `false` only after testing. Destructive deletes also require `DESTRUCTIVE_REMEDIATION_ENABLED=true`.

## API

- `GET /api/health`: token and scan health.
- `GET /api/alerts?status=open`: alert summary and list.
- `POST /api/scans`: queue an immediate scan.
- `POST /api/alerts/{alert_id}/remediate`: execute the registered remediation action.

## Testing

The unit tests avoid live Coda calls.

```bash
python -m unittest
```

## Logging And Auditability

Application logs are written to `LOG_FILE` with rotation. Alert state, scan runs, and remediation audit entries are persisted in SQLite. The `audit_log` table records the action, status, message, alert ID, timestamp, and payload for every remediation attempt.

## AI Tool Usage

This solution was developed with OpenAI Codex assistance. Codex was used to scaffold the app, implement detection/remediation modules, build the dashboard, write tests, and draft this README. The Coda API integration points were cross-checked against the official Coda API reference.


