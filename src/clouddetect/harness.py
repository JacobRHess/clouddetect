"""Turn one (detection, fixture) pair into a verdict on one engine.

The contract is strict and engine-agnostic:

* An `alert` fixture must make the detection fire. A detection that stays quiet
  on its own attack sample is broken.
* A `clean` fixture must not make it fire. This is the half people skip, and it
  is the half that catches a detection that "works" only because it matches
  everything.

A detection is only considered proven when every fixture passes on *both*
engines. A pass on Splunk and a miss on OpenSearch is a portability bug in the
rule, surfaced as a failed verdict rather than hidden.
"""

from __future__ import annotations

from dataclasses import dataclass

from clouddetect.engine import Engine, load_events
from clouddetect.manifest import Detection, Expect, Fixture


@dataclass(frozen=True, slots=True)
class Verdict:
    detection_id: str
    engine: str
    fixture: str
    expect: Expect
    fired: bool
    passed: bool

    @property
    def detail(self) -> str:
        if self.expect is Expect.ALERT:
            return (
                "fired on its attack sample as required"
                if self.passed
                else "did NOT fire on its attack sample"
            )
        return (
            "stayed silent on the benign sample"
            if self.passed
            else "fired on a benign sample that must not alert"
        )


def evaluate(detection: Detection, fixture: Fixture, engine: Engine) -> Verdict:
    events = load_events(fixture.events)
    fired = engine.replay(detection, events)
    passed = fired if fixture.expect is Expect.ALERT else not fired
    return Verdict(
        detection_id=detection.id,
        engine=engine.name,
        fixture=fixture.name,
        expect=fixture.expect,
        fired=fired,
        passed=passed,
    )
