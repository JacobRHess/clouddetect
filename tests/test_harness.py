"""The verdict logic, exercised with a fake engine so no SIEM is needed.

The real engines are proven by the replay job. Here we only check that the
harness turns an engine's fire/no-fire into the right pass/fail for both the
alert and the clean expectations.
"""

from __future__ import annotations

from typing import Any

import pytest

from clouddetect.harness import evaluate
from clouddetect.manifest import Detection, Expect, load


class FakeEngine:
    name = "fake"

    def __init__(self, *, fires: bool) -> None:
        self._fires = fires

    def wait_ready(self) -> None:  # pragma: no cover - not called here
        pass

    def replay(self, detection: Detection, events: list[dict[str, Any]]) -> bool:
        return self._fires


def _first_detection() -> Detection:
    return load()[0]


@pytest.mark.parametrize(
    ("expect", "fires", "should_pass"),
    [
        (Expect.ALERT, True, True),  # alert fixture fires -> pass
        (Expect.ALERT, False, False),  # alert fixture silent -> fail
        (Expect.CLEAN, False, True),  # benign fixture silent -> pass
        (Expect.CLEAN, True, False),  # benign fixture fires -> fail
    ],
)
def test_verdict(expect: Expect, fires: bool, should_pass: bool) -> None:
    det = _first_detection()
    fixture = next(f for f in det.fixtures if f.expect is expect)
    verdict = evaluate(det, fixture, FakeEngine(fires=fires))
    assert verdict.passed is should_pass
    assert verdict.fired is fires
    assert verdict.detail  # both branches produce a human sentence
