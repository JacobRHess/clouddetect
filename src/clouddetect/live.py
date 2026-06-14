"""The live loop: detonate a real attack, pull the CloudTrail it produced, and
prove the detection fires on real attacker telemetry instead of a fixture.

This is the manual, AWS-touching counterpart to the fixture replay. It never
runs in CI - it needs credentials for a *dedicated sandbox account* and the
stratus-red-team binary on PATH. The fixture loop is the proof CI enforces; this
is the proof you run by hand to show the rules hold on the real thing.

The flow, behind `clouddetect detonate <technique>`:

1. `stratus detonate <technique>` performs the attack in the sandbox.
2. CloudTrail records the API calls it made.
3. We poll CloudTrail LookupEvents for those event names (management events can
   take several minutes to surface) and normalise them into the same shape as a
   fixture.
4. We replay them through the live engines and report whether the mapped
   detection fired.
5. `stratus cleanup <technique>` tears the attack infrastructure back down.

Only `normalize_lookup_events` and the technique map are pure and unit-tested;
the boto3 and subprocess calls are integration glue, run by hand.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from clouddetect.engine import Engine

# Stratus Red Team technique id -> the clouddetect detection its CloudTrail
# trips. Not every detection has a Stratus counterpart (there is no built-in
# GuardDuty-disable or KMS-delete technique, for instance); this maps the ones
# that do, and `clouddetect detonate` rejects anything not listed here.
STRATUS_MAP: dict[str, str] = {
    "aws.defense-evasion.cloudtrail-stop": "cloudtrail-logging-disabled",
    "aws.defense-evasion.cloudtrail-delete": "cloudtrail-logging-disabled",
    "aws.persistence.iam-create-admin-user": "iam-attach-admin-policy",
}

# The CloudTrail event names each technique produces that we should poll for.
TECHNIQUE_EVENT_NAMES: dict[str, tuple[str, ...]] = {
    "aws.defense-evasion.cloudtrail-stop": ("StopLogging",),
    "aws.defense-evasion.cloudtrail-delete": ("DeleteTrail",),
    "aws.persistence.iam-create-admin-user": ("AttachUserPolicy",),
}


class StratusError(RuntimeError):
    """The stratus binary was missing or exited unsuccessfully."""


class LiveError(RuntimeError):
    """The live loop could not complete."""


@dataclass(frozen=True, slots=True)
class DetonationResult:
    technique: str
    detection_id: str
    event_count: int
    fired: dict[str, bool]  # engine name -> did the detection fire


def normalize_lookup_events(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn a CloudTrail LookupEvents response into raw event dicts.

    LookupEvents wraps the actual record as a JSON string under `CloudTrailEvent`;
    we parse each one back into the same shape a fixture stores, so the engines
    cannot tell a detonated event from a hand-authored one. Anything missing or
    unparseable is skipped rather than crashing the loop.
    """
    events: list[dict[str, Any]] = []
    for entry in payload.get("Events", []):
        raw = entry.get("CloudTrailEvent") if isinstance(entry, dict) else None
        if not isinstance(raw, str):
            continue
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            events.append(record)
    return events


def detection_for(technique: str) -> str:
    """The detection a technique maps to, or raise if it is not supported."""
    if technique not in STRATUS_MAP:
        supported = ", ".join(sorted(STRATUS_MAP))
        raise LiveError(f"no detection mapped for {technique!r}; supported: {supported}")
    return STRATUS_MAP[technique]


def _run_stratus(  # pragma: no cover - shells out to the stratus binary
    action: str,
    technique: str,
    *,
    binary: str = "stratus",
    timeout: int = 600,
    region: str | None = None,
) -> str:
    argv = [binary, action, technique]
    # stratus (AWS Go SDK) reads the region from AWS_REGION, not ~/.aws/config,
    # so pass it explicitly or it fails with "you have not set your region".
    env = os.environ.copy()
    if region:
        env["AWS_REGION"] = region
    try:
        proc = subprocess.run(  # noqa: S603
            argv, capture_output=True, text=True, timeout=timeout, check=False, env=env
        )
    except FileNotFoundError as exc:
        raise StratusError(f"{binary!r} not found on PATH; install stratus-red-team") from exc
    except subprocess.TimeoutExpired as exc:
        raise StratusError(f"stratus {action} exceeded {timeout}s") from exc
    if proc.returncode != 0:
        # stratus logs failures to stdout, not stderr, so include both or the
        # error is an unhelpful blank line.
        detail = (proc.stderr.strip() or proc.stdout.strip() or "no output")[-800:]
        raise StratusError(f"stratus {action} {technique} failed: {detail}")
    return proc.stdout


class CloudTrailReader:  # pragma: no cover - talks to AWS
    """Poll CloudTrail LookupEvents for the events a detonation produced."""

    def __init__(self, region: str | None = None) -> None:
        import boto3

        self._client = boto3.client("cloudtrail", region_name=region)

    def poll(
        self,
        event_names: tuple[str, ...],
        since: datetime,
        *,
        timeout: int = 900,
        interval: int = 30,
    ) -> list[dict[str, Any]]:
        """Wait for at least one matching event, returning all found, or [] on timeout.

        Management events can take several minutes to appear, so this polls until
        the deadline. Each event name is a separate LookupAttributes query because
        the API allows only one attribute per call.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found: list[dict[str, Any]] = []
            for name in event_names:
                payload = self._client.lookup_events(
                    LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}],
                    StartTime=since,
                )
                found.extend(normalize_lookup_events(payload))
            if found:
                return found
            time.sleep(interval)
        return []


def detonate(  # pragma: no cover - drives stratus + AWS end to end
    technique: str,
    engines: tuple[Engine, ...],
    *,
    region: str | None = None,
    keep: bool = False,
    timeout: int = 900,
) -> DetonationResult:
    """Detonate one technique, replay its real CloudTrail through the engines."""
    import boto3

    from clouddetect.manifest import load

    detection_id = detection_for(technique)
    detection = next(d for d in load() if d.id == detection_id)
    event_names = TECHNIQUE_EVENT_NAMES.get(technique, ())

    # stratus needs an explicit region; resolve it once from the flag or config.
    resolved = region or boto3.Session().region_name
    if not resolved:
        raise LiveError("no AWS region set; pass --region or configure a default region")

    reader = CloudTrailReader(resolved)
    since = datetime.now(UTC)
    _run_stratus("detonate", technique, region=resolved)
    try:
        events = reader.poll(event_names, since, timeout=timeout)
        if not events:
            raise LiveError(
                f"no CloudTrail events for {technique} within {timeout}s "
                f"(management events can lag; try a longer --timeout)"
            )
        fired = {engine.name: engine.replay(detection, events) for engine in engines}
    finally:
        if not keep:
            _run_stratus("cleanup", technique, region=resolved)

    return DetonationResult(
        technique=technique,
        detection_id=detection_id,
        event_count=len(events),
        fired=fired,
    )
