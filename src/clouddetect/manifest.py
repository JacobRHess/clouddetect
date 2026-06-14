"""Load and validate detections.yaml, the single source of truth.

The harness, the CLI, the test suite and the ATT&CK doc are all driven by this
file. Adding a detection means adding an entry here plus a Sigma rule and two
fixtures (one attack, one benign) - nothing else.

Every path in the manifest is confined to the repository root: it must be
relative, must not climb out with `..`, and must point at a file that exists.
A manifest that references a path outside the repo is a hard error, not a
detection that mysteriously never fires.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "detections.yaml"


class ManifestError(ValueError):
    """The manifest is malformed or references something that does not exist."""


class Expect(Enum):
    ALERT = "alert"
    CLEAN = "clean"


class LogSource(Enum):
    """Which log family a detection reads, fixing its index and sourcetype."""

    CLOUDTRAIL = "cloudtrail"
    OKTA = "okta"
    ENTRA = "entra"


@dataclass(frozen=True, slots=True)
class Fixture:
    events: Path
    expect: Expect

    @property
    def name(self) -> str:
        return self.events.name


@dataclass(frozen=True, slots=True)
class Detection:
    id: str
    title: str
    logsource: LogSource
    rule: Path
    attack: tuple[str, ...]
    fixtures: tuple[Fixture, ...]


def _confine(raw: str, *, field: str, ctx: str) -> Path:
    """Resolve a manifest-relative path, refusing anything outside the repo."""
    candidate = (REPO_ROOT / raw).resolve()
    try:
        candidate.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise ManifestError(f"{ctx}: {field} {raw!r} escapes the repository root") from exc
    if not candidate.is_file():
        raise ManifestError(f"{ctx}: {field} {raw!r} does not exist")
    return candidate


def _require(mapping: dict[str, Any], key: str, ctx: str) -> Any:
    if key not in mapping:
        raise ManifestError(f"{ctx}: missing required key {key!r}")
    return mapping[key]


def _parse_fixture(raw: dict[str, Any], ctx: str) -> Fixture:
    events = _confine(str(_require(raw, "events", ctx)), field="events", ctx=ctx)
    try:
        expect = Expect(str(_require(raw, "expect", ctx)))
    except ValueError as exc:
        raise ManifestError(f"{ctx}: expect must be 'alert' or 'clean'") from exc
    return Fixture(events=events, expect=expect)


def _parse_detection(raw: dict[str, Any]) -> Detection:
    det_id = str(_require(raw, "id", "detection"))
    ctx = f"detection {det_id!r}"
    try:
        logsource = LogSource(str(_require(raw, "logsource", ctx)))
    except ValueError as exc:
        raise ManifestError(
            f"{ctx}: logsource must be one of {[s.value for s in LogSource]}"
        ) from exc

    attack = tuple(str(t) for t in raw.get("attack", []))
    fixtures_raw = _require(raw, "fixtures", ctx)
    if not isinstance(fixtures_raw, list) or not fixtures_raw:
        raise ManifestError(f"{ctx}: fixtures must be a non-empty list")
    fixtures = tuple(_parse_fixture(f, ctx) for f in fixtures_raw)

    expects = {f.expect for f in fixtures}
    if Expect.ALERT not in expects or Expect.CLEAN not in expects:
        raise ManifestError(f"{ctx}: needs at least one 'alert' and one 'clean' fixture")

    return Detection(
        id=det_id,
        title=str(_require(raw, "title", ctx)),
        logsource=logsource,
        rule=_confine(str(_require(raw, "rule", ctx)), field="rule", ctx=ctx),
        attack=attack,
        fixtures=fixtures,
    )


def load(path: Path = MANIFEST_PATH) -> tuple[Detection, ...]:
    """Parse and validate the manifest, returning every detection."""
    if not path.is_file():
        raise ManifestError(f"manifest not found at {path}")
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ManifestError("manifest root must be a mapping")
    detections_raw = doc.get("detections")
    if not isinstance(detections_raw, list) or not detections_raw:
        raise ManifestError("manifest must list at least one detection")

    detections = tuple(_parse_detection(d) for d in detections_raw)

    seen: set[str] = set()
    for det in detections:
        if det.id in seen:
            raise ManifestError(f"duplicate detection id {det.id!r}")
        seen.add(det.id)
    return detections
