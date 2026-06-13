"""Replay one fixture's events through a SIEM and report whether a detection fired.

Two backends, one boundary. The harness only ever sees
`Engine.replay(detection, events) -> bool`: did this detection's query match any
of these events? Each backend converts the detection's Sigma rule into its own
query language (SPL for Splunk, Lucene for OpenSearch) and evaluates it against
the fixture in isolation, so neither the harness nor the tests care which engine
ran or what the query looked like.

Isolation differs by backend because the cheap primitive differs. OpenSearch
gets a throwaway index per replay. Splunk shares one index and tags every event
with a per-replay marker, scoping the search to it. Either way, a replay only
ever sees the one fixture's events.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from clouddetect import sigma
from clouddetect.manifest import Detection, LogSource
from clouddetect.opensearch import OpenSearchClient
from clouddetect.splunk import SplunkClient

# Splunk sourcetype per log family. The lab's props.conf sets KV_MODE=json on
# both so the nested CloudTrail and Okta fields the rules reference are
# extracted at search time.
_SPLUNK_SOURCETYPE = {
    LogSource.CLOUDTRAIL: "aws:cloudtrail",
    LogSource.OKTA: "okta:system",
}


class EngineError(RuntimeError):
    """The engine could not run, or returned something we cannot interpret."""


def load_events(path: Path) -> list[dict[str, Any]]:
    """Read a fixture file as a JSON array of event objects."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list) or not all(isinstance(e, dict) for e in raw):
        raise EngineError(f"{path.name}: fixture must be a JSON array of event objects")
    return raw


@runtime_checkable
class Engine(Protocol):
    """Anything that can replay a fixture against a detection and report a hit."""

    name: str

    def wait_ready(self) -> None: ...

    def replay(self, detection: Detection, events: list[dict[str, Any]]) -> bool: ...


class SplunkEngine:
    name = "splunk"

    def __init__(self, client: SplunkClient | None = None) -> None:
        self.client = client or SplunkClient()

    def wait_ready(self) -> None:
        self.client.wait_ready()

    def replay(self, detection: Detection, events: list[dict[str, Any]]) -> bool:
        run = uuid.uuid4().hex
        spl = sigma.to_spl(detection.rule.read_text(encoding="utf-8"))
        sourcetype = _SPLUNK_SOURCETYPE[detection.logsource]
        self.client.post_events(events, sourcetype=sourcetype, run=run)
        # HEC accepts before indexing finishes; wait until the run's events are
        # searchable so a slow index never looks like a detection miss.
        self.client.wait_for_count(run, expected=len(events))
        rows = self.client.search(f'search index={self.client.config.index} cd_run="{run}" ({spl})')
        return len(rows) > 0


class OpenSearchEngine:
    name = "opensearch"

    def __init__(self, client: OpenSearchClient | None = None) -> None:
        self.client = client or OpenSearchClient()

    def wait_ready(self) -> None:
        self.client.wait_ready()

    def replay(self, detection: Detection, events: list[dict[str, Any]]) -> bool:
        index = f"clouddetect-{uuid.uuid4().hex}"
        lucene = sigma.to_lucene(detection.rule.read_text(encoding="utf-8"))
        try:
            self.client.index_events(index, events)
            return self.client.count(index, lucene) > 0
        finally:
            self.client.drop(index)
