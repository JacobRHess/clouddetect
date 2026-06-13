"""The manifest loads, validates, and every detection converts on both backends.

These run offline (no Splunk, no OpenSearch). They are the gate that a new
detection is wired up correctly before the replay job ever boots an engine.
"""

from __future__ import annotations

import pytest

from clouddetect import sigma
from clouddetect.engine import load_events
from clouddetect.manifest import Detection, Expect, load


@pytest.fixture(scope="module")
def detections() -> tuple[Detection, ...]:
    return load()


def test_manifest_is_non_empty(detections: tuple[Detection, ...]) -> None:
    assert detections


def test_ids_are_unique(detections: tuple[Detection, ...]) -> None:
    ids = [d.id for d in detections]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("which", ["alert", "clean"])
def test_each_detection_has_both_fixture_kinds(
    detections: tuple[Detection, ...], which: str
) -> None:
    want = Expect(which)
    for det in detections:
        assert any(f.expect is want for f in det.fixtures), f"{det.id} missing a {which} fixture"


def test_every_fixture_is_a_json_event_array(detections: tuple[Detection, ...]) -> None:
    for det in detections:
        for fx in det.fixtures:
            events = load_events(fx.events)
            assert events, f"{fx.name} is empty"


def test_attack_tags_look_like_techniques(detections: tuple[Detection, ...]) -> None:
    for det in detections:
        for tag in det.attack:
            assert tag.startswith("T"), f"{det.id}: {tag!r} is not a Txxxx technique id"


def test_converts_to_spl(detections: tuple[Detection, ...]) -> None:
    for det in detections:
        spl = sigma.to_spl(det.rule.read_text(encoding="utf-8"))
        assert spl.strip(), f"{det.id} produced empty SPL"


def test_converts_to_lucene(detections: tuple[Detection, ...]) -> None:
    for det in detections:
        lucene = sigma.to_lucene(det.rule.read_text(encoding="utf-8"))
        assert lucene.strip(), f"{det.id} produced empty Lucene"
