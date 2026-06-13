"""Minimal OpenSearch client for the lab: bulk index, query-string count, no SDK.

Each fixture is replayed into its own throwaway index, queried with the Lucene
string the Sigma rule converts to, and the index is dropped afterwards. Per-run
index isolation is cheap in OpenSearch, so unlike the Splunk side there is no
shared index and no run marker to carry: the index *is* the isolation boundary.

The lab's single-node OpenSearch runs with the security plugin disabled on
localhost, so calls are plain HTTP with no auth by default. Point at a secured
cluster with CD_OS_URL / CD_OS_USER / CD_OS_PASSWORD.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

import requests


class OpenSearchError(RuntimeError):
    """OpenSearch was unreachable or returned something we cannot use."""


@dataclass(frozen=True, slots=True)
class OpenSearchConfig:
    url: str = field(default_factory=lambda: os.environ.get("CD_OS_URL", "http://localhost:9200"))
    user: str | None = field(default_factory=lambda: os.environ.get("CD_OS_USER") or None)
    password: str | None = field(default_factory=lambda: os.environ.get("CD_OS_PASSWORD") or None)
    timeout: int = 60
    verify: bool = field(
        default_factory=lambda: os.environ.get("CD_OS_VERIFY", "").lower() in ("1", "true", "yes")
    )


class OpenSearchClient:
    def __init__(self, config: OpenSearchConfig | None = None) -> None:
        self.config = config or OpenSearchConfig()
        self._session = requests.Session()
        self._session.verify = self.config.verify
        if self.config.user and self.config.password:
            self._session.auth = (self.config.user, self.config.password)

    def _url(self, path: str) -> str:
        return f"{self.config.url.rstrip('/')}/{path.lstrip('/')}"

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        try:
            resp = self._session.request(
                method, self._url(path), timeout=self.config.timeout, **kwargs
            )
        except requests.RequestException as exc:
            raise OpenSearchError(f"{method} {path} failed: {exc}") from exc
        return resp

    def wait_ready(self, attempts: int = 40, delay: float = 3.0) -> None:
        for _ in range(attempts):
            try:
                resp = self._request("GET", "/_cluster/health")
                if resp.status_code == 200 and resp.json().get("status") in ("green", "yellow"):
                    return
            except (OpenSearchError, ValueError):
                pass
            time.sleep(delay)
        raise OpenSearchError(f"OpenSearch not ready after {attempts} attempts")

    def index_events(self, index: str, events: list[dict[str, Any]]) -> int:
        """Bulk-index events into a fresh index and refresh so they're searchable."""
        self._request("DELETE", f"/{index}")  # best effort; ignore 404
        lines: list[str] = []
        for event in events:
            lines.append(json.dumps({"index": {}}))
            lines.append(json.dumps(event))
        body = "\n".join(lines) + "\n"
        resp = self._request(
            "POST",
            f"/{index}/_bulk?refresh=true",
            data=body,
            headers={"Content-Type": "application/x-ndjson"},
        )
        if resp.status_code not in (200, 201):
            raise OpenSearchError(f"bulk index returned {resp.status_code}: {resp.text[:200]}")
        payload = resp.json()
        if payload.get("errors"):
            raise OpenSearchError(f"bulk index reported item errors: {json.dumps(payload)[:300]}")
        return len(events)

    def count(self, index: str, lucene: str) -> int:
        """Count documents in `index` matching a Lucene query string."""
        resp = self._request(
            "POST",
            f"/{index}/_count",
            json={"query": {"query_string": {"query": lucene, "analyze_wildcard": True}}},
        )
        if resp.status_code != 200:
            raise OpenSearchError(f"count returned {resp.status_code}: {resp.text[:200]}")
        return int(resp.json().get("count", 0))

    def drop(self, index: str) -> None:
        self._request("DELETE", f"/{index}")
