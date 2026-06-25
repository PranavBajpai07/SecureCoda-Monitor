from __future__ import annotations

import json
import logging
import time
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


logger = logging.getLogger(__name__)


class CodaApiError(RuntimeError):
    pass


class CodaClient:
    def __init__(self, api_token: str, base_url: str = "https://coda.io/apis/v1", timeout: int = 30) -> None:
        self.api_token = api_token
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def list_docs(self, workspace_id: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": 100}
        if workspace_id:
            params["workspaceId"] = workspace_id
        return self._paginate("/docs", params=params)

    def list_permissions(self, doc_id: str) -> list[dict[str, Any]]:
        return self._paginate(f"/docs/{doc_id}/acl/permissions", params={"limit": 100})

    def get_acl_settings(self, doc_id: str) -> dict[str, Any]:
        return self._request("GET", f"/docs/{doc_id}/acl/settings")

    def update_acl_settings(self, doc_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("PATCH", f"/docs/{doc_id}/acl/settings", payload)

    def delete_permission(self, doc_id: str, permission_id: str) -> dict[str, Any]:
        return self._request("DELETE", f"/docs/{doc_id}/acl/permissions/{permission_id}")

    def unpublish_doc(self, doc_id: str) -> dict[str, Any]:
        return self._request("DELETE", f"/docs/{doc_id}/publish")

    def delete_doc(self, doc_id: str) -> dict[str, Any]:
        return self._request("DELETE", f"/docs/{doc_id}")

    def list_pages(self, doc_id: str) -> list[dict[str, Any]]:
        return self._paginate(f"/docs/{doc_id}/pages", params={"limit": 100})

    def export_page_content(self, doc_id: str, page_id: str, output_format: str = "markdown") -> str:
        export = self._request(
            "POST",
            f"/docs/{doc_id}/pages/{page_id}/export",
            {"outputFormat": output_format},
        )
        request_id = export.get("id") or export.get("requestId")
        if not request_id:
            raise CodaApiError(f"Missing export request id for page {page_id}")

        for _ in range(10):
            status = self._request("GET", f"/docs/{doc_id}/pages/{page_id}/export/{request_id}")
            if status.get("status") == "complete" and status.get("downloadLink"):
                return self._download(status["downloadLink"])
            if status.get("status") == "failed":
                raise CodaApiError(status.get("error") or f"Export failed for page {page_id}")
            time.sleep(1)

        raise CodaApiError(f"Timed out waiting for export of page {page_id}")

    def delete_page_content(self, doc_id: str, page_id: str) -> dict[str, Any]:
        return self._request("DELETE", f"/docs/{doc_id}/pages/{page_id}/content")

    def list_tables(self, doc_id: str) -> list[dict[str, Any]]:
        return self._paginate(f"/docs/{doc_id}/tables", params={"limit": 100})

    def list_rows(self, doc_id: str, table_id: str, max_rows: int) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        params: dict[str, Any] = {
            "limit": min(max_rows, 500),
            "useColumnNames": "true",
            "valueFormat": "simpleWithArrays",
        }
        page_token: str | None = None
        while True:
            if page_token:
                params = {"pageToken": page_token}
            response = self._request("GET", f"/docs/{doc_id}/tables/{table_id}/rows", params=params)
            rows.extend(response.get("items", []))
            if len(rows) >= max_rows:
                return rows[:max_rows]
            page_token = response.get("nextPageToken")
            if not page_token:
                return rows

    def delete_row(self, doc_id: str, table_id: str, row_id: str) -> dict[str, Any]:
        return self._request("DELETE", f"/docs/{doc_id}/tables/{table_id}/rows/{row_id}")

    def _paginate(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page_token: str | None = None
        current_params = dict(params or {})
        while True:
            if page_token:
                current_params = {"pageToken": page_token}
            response = self._request("GET", path, params=current_params)
            items.extend(response.get("items", []))
            page_token = response.get("nextPageToken")
            if not page_token:
                return items

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        if params:
            url = f"{url}?{urlencode(params)}"
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Accept": "application/json",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"

        for attempt in range(4):
            request = Request(url, data=body, method=method, headers=headers)
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    data = response.read()
                    if not data:
                        return {}
                    return json.loads(data.decode("utf-8"))
            except HTTPError as exc:
                if exc.code == 429 and attempt < 3:
                    retry_after = int(exc.headers.get("Retry-After", "2"))
                    logger.warning("Coda API rate limited; retrying in %s seconds", retry_after)
                    time.sleep(retry_after)
                    continue
                message = exc.read().decode("utf-8", errors="replace")
                raise CodaApiError(f"Coda API {method} {path} failed: {exc.code} {message}") from exc

        raise CodaApiError(f"Coda API {method} {path} failed after retries")

    def _download(self, url: str) -> str:
        request = Request(url, headers={"Accept": "text/plain, text/html, */*"})
        with urlopen(request, timeout=self.timeout) as response:
            return response.read().decode("utf-8", errors="replace")

