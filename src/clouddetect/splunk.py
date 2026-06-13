"""Minimal Splunk client for the lab: HEC event posting and REST search, no SDK.

Adapted from the purpleloop harness. It targets the local lab Splunk, whose
certificate is self-signed, so TLS verification is off by default and is turned
on with CD_SPLUNK_VERIFY=true for a trusted endpoint. Every call maps a
transport failure to a SplunkError so the harness reports it cleanly rather than
leaking a requests exception.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_DEV_HEC_TOKEN = "00000000-0000-0000-0000-000000000000"  # noqa: S105  # nosec B105


class SplunkError(RuntimeError):
    """Splunk was unreachable or returned something we cannot use."""


@dataclass(frozen=True, slots=True)
class SplunkConfig:
    host: str = field(default_factory=lambda: os.environ.get("CD_SPLUNK_HOST", "localhost"))
    hec_port: int = field(default_factory=lambda: int(os.environ.get("CD_HEC_PORT", "8088")))
    api_port: int = field(default_factory=lambda: int(os.environ.get("CD_API_PORT", "8089")))
    username: str = "admin"
    password: str = field(default_factory=lambda: os.environ.get("CD_SPLUNK_PASSWORD", "changeme"))
    hec_token: str = _DEV_HEC_TOKEN
    index: str = "clouddetect"
    timeout: int = 60
    verify: bool = field(
        default_factory=lambda: (
            os.environ.get("CD_SPLUNK_VERIFY", "").lower() in ("1", "true", "yes")
        )
    )


class SplunkClient:
    def __init__(self, config: SplunkConfig | None = None) -> None:
        self.config = config or SplunkConfig()
        self._session = requests.Session()
        self._session.verify = self.config.verify

    def _api(self, path: str) -> str:
        return f"https://{self.config.host}:{self.config.api_port}{path}"

    def wait_ready(self, attempts: int = 40, delay: float = 5.0) -> None:
        for _ in range(attempts):
            try:
                resp = self._session.get(
                    self._api("/services/server/info"),
                    auth=(self.config.username, self.config.password),
                    params={"output_mode": "json"},
                    timeout=self.config.timeout,
                )
                if resp.status_code == 200:
                    return
            except requests.RequestException:
                pass
            time.sleep(delay)
        raise SplunkError(f"Splunk not ready after {attempts} attempts")

    def post_events(self, events: list[dict[str, Any]], sourcetype: str, run: str) -> int:
        """Send events to HEC, tagging each with a per-run marker for isolation."""
        url = f"https://{self.config.host}:{self.config.hec_port}/services/collector/event"
        lines: list[str] = []
        for event in events:
            tagged = {**event, "cd_run": run}
            envelope: dict[str, Any] = {
                "event": tagged,
                "index": self.config.index,
                "sourcetype": sourcetype,
            }
            if "_time" in event:
                envelope["time"] = event["_time"]
            lines.append(json.dumps(envelope))
        try:
            resp = self._session.post(
                url,
                headers={"Authorization": f"Splunk {self.config.hec_token}"},
                data="\n".join(lines),
                timeout=self.config.timeout,
            )
        except requests.RequestException as exc:
            raise SplunkError(f"HEC post failed: {exc}") from exc
        if resp.status_code != 200:
            raise SplunkError(f"HEC returned {resp.status_code}: {resp.text[:200]}")
        return len(events)

    def search(self, spl: str, earliest: str = "-10y", latest: str = "now") -> list[dict[str, Any]]:
        query = spl.strip()
        if not query.startswith("|") and not query.lower().startswith("search"):
            query = f"search {query}"
        try:
            resp = self._session.post(
                self._api("/services/search/jobs"),
                auth=(self.config.username, self.config.password),
                data={
                    "search": query,
                    "earliest_time": earliest,
                    "latest_time": latest,
                    "exec_mode": "oneshot",
                    "output_mode": "json",
                    "count": 0,
                },
                timeout=self.config.timeout,
            )
        except requests.RequestException as exc:
            raise SplunkError(f"search failed: {exc}") from exc
        if resp.status_code != 200:
            raise SplunkError(f"search returned {resp.status_code}: {resp.text[:200]}")
        try:
            payload = resp.json()
        except ValueError as exc:
            raise SplunkError(f"search results were not JSON: {exc}") from exc
        rows = payload.get("results", []) if isinstance(payload, dict) else []
        return [row for row in rows if isinstance(row, dict)]

    def count(self, run: str) -> int:
        rows = self.search(f'search index={self.config.index} cd_run="{run}" | stats count')
        if not rows:
            return 0
        try:
            return int(rows[0].get("count", 0))
        except (ValueError, TypeError):
            return 0

    def wait_for_count(
        self, run: str, expected: int, timeout: float = 180.0, poll: float = 3.0
    ) -> None:
        """Wait until at least `expected` events for this run are searchable."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.count(run) >= expected:
                return
            time.sleep(poll)
