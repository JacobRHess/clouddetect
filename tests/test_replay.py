"""Replay every fixture through both real engines.

This is the half of the suite that needs infrastructure: a live Splunk and a
live OpenSearch (the lab, or the CI validate job). It is marked `replay` and is
deselected by the default `pytest -q` run, so the offline gate stays fast.

Each detection's attack fixture must fire the rule and its benign fixture must
stay silent - on *both* engines. A parametrized id reads like
`splunk-iam_attach_admin_policy.alert`, so a failure names the engine and the
exact fixture that broke.
"""

from __future__ import annotations

import pytest

from clouddetect.engine import Engine, OpenSearchEngine, SplunkEngine
from clouddetect.harness import evaluate
from clouddetect.manifest import Detection, Fixture, load

_DETECTIONS = load()
_ENGINES: tuple[Engine, ...] = (SplunkEngine(), OpenSearchEngine())

_CASES = [
    pytest.param(det, fx, eng, id=f"{eng.name}-{fx.events.stem}")
    for det in _DETECTIONS
    for fx in det.fixtures
    for eng in _ENGINES
]


@pytest.fixture(scope="session", autouse=True)
def _engines_ready() -> None:
    for engine in _ENGINES:
        engine.wait_ready()


@pytest.mark.replay
@pytest.mark.parametrize(("detection", "fixture", "engine"), _CASES)
def test_fixture_behaves_as_declared(
    detection: Detection, fixture: Fixture, engine: Engine
) -> None:
    verdict = evaluate(detection, fixture, engine)
    assert verdict.passed, (
        f"{detection.id} on {engine.name}: {fixture.name} {verdict.detail} (fired={verdict.fired})"
    )
