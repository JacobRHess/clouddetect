"""Generate the ATT&CK coverage doc and Navigator layer from the manifest.

The mapping in the docs is generated, not hand-maintained. `python -m
clouddetect.attackdoc` prints docs/ATTACK.md; CI diffs the result against the
committed copy on every push, so the table cannot drift away from the manifest.
The same data renders an ATT&CK Navigator layer (`--layer`) you can drop onto
the Cloud matrix.
"""

from __future__ import annotations

import json
from pathlib import Path

from clouddetect.manifest import load

# ATT&CK has no public name lookup we want to vendor, so the names used in the
# table live next to the techniques the pack actually claims. Adding a detection
# that uses a new technique adds a line here, or generation fails loudly rather
# than shipping a blank cell.
TECHNIQUE_NAMES = {
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1098": "Account Manipulation",
    "T1098.001": "Account Manipulation: Additional Cloud Credentials",
    "T1098.003": "Account Manipulation: Additional Cloud Roles",
    "T1485": "Data Destruction",
    "T1556.006": "Modify Authentication Process: Multi-Factor Authentication",
    "T1562.008": "Impair Defenses: Disable or Modify Cloud Logs",
}

_COVERED_COLOR = "#1f6feb"


def _check_names() -> None:
    missing = sorted({t for det in load() for t in det.attack if t not in TECHNIQUE_NAMES})
    if missing:
        raise ValueError(
            f"no ATT&CK name on file for {missing}; add them to TECHNIQUE_NAMES "
            f"so the doc cannot ship a blank cell"
        )


def render_markdown() -> str:
    _check_names()
    lines = [
        "# ATT&CK coverage",
        "",
        "Generated from `detections.yaml`. Regenerate after manifest changes:",
        "",
        "```bash",
        "uv run python -m clouddetect.attackdoc > docs/ATTACK.md",
        "```",
        "",
        "| Technique | Name | Detection | Source |",
        "|-----------|------|-----------|--------|",
    ]
    for det in load():
        for technique in det.attack:
            lines.append(
                f"| {technique} | {TECHNIQUE_NAMES[technique]} | {det.id} | {det.logsource.value} |"
            )
    return "\n".join(lines) + "\n"


def render_layer() -> dict[str, object]:
    _check_names()
    by_technique: dict[str, list[str]] = {}
    for det in load():
        for technique in det.attack:
            by_technique.setdefault(technique, []).append(det.id)
    techniques = [
        {
            "techniqueID": tid,
            "score": len(dets),
            "color": _COVERED_COLOR,
            "comment": ", ".join(sorted(dets)),
            "enabled": True,
        }
        for tid, dets in sorted(by_technique.items())
    ]
    return {
        "name": "clouddetect coverage",
        "description": "Cloud and identity detections proven against Splunk and OpenSearch.",
        "domain": "enterprise-attack",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", _COVERED_COLOR], "minValue": 0, "maxValue": 3},
        "legendItems": [{"label": "covered by a clouddetect detection", "color": _COVERED_COLOR}],
        "hideDisabled": False,
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="clouddetect.attackdoc")
    parser.add_argument("--layer", type=Path, help="write the Navigator layer JSON here")
    args = parser.parse_args()
    if args.layer is not None:
        args.layer.write_text(json.dumps(render_layer(), indent=2) + "\n", encoding="utf-8")
        return 0
    print(render_markdown(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
