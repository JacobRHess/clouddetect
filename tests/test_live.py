"""The pure parts of the live loop: the technique map and event normalisation.

The boto3 and stratus calls are integration glue run by hand against a sandbox;
what we can test offline is that the map points at real detections and that a
CloudTrail LookupEvents response is parsed back into fixture-shaped records.
"""

from __future__ import annotations

import json

import pytest

from clouddetect import live
from clouddetect.manifest import load


def test_every_mapped_detection_exists() -> None:
    known = {d.id for d in load()}
    for technique, detection_id in live.STRATUS_MAP.items():
        assert detection_id in known, f"{technique} maps to unknown detection {detection_id!r}"


def test_every_technique_has_event_names() -> None:
    for technique in live.STRATUS_MAP:
        assert live.TECHNIQUE_EVENT_NAMES.get(technique), f"{technique} has no event names"


def test_detection_for_rejects_unknown() -> None:
    with pytest.raises(live.LiveError, match="no detection mapped"):
        live.detection_for("aws.discovery.not-a-real-technique")


def test_normalize_parses_cloudtrail_events() -> None:
    record = {"eventName": "StopLogging", "eventSource": "cloudtrail.amazonaws.com"}
    payload = {
        "Events": [
            {"EventName": "StopLogging", "CloudTrailEvent": json.dumps(record)},
            {"EventName": "Broken", "CloudTrailEvent": "{not valid json"},
            {"EventName": "Missing"},  # no CloudTrailEvent at all
        ]
    }
    events = live.normalize_lookup_events(payload)
    assert events == [record]


def test_normalize_handles_empty() -> None:
    assert live.normalize_lookup_events({}) == []
