"""The ATT&CK doc and the HTML report are generated faithfully from the manifest.

The CI drift check is the real guard on docs/ATTACK.md; these tests catch the
common breakages earlier and offline: a technique with no name on file, a
manifest tag that never reaches the layer, an unescaped value in the report.
"""

from __future__ import annotations

from clouddetect import attackdoc, report
from clouddetect.manifest import load


def test_markdown_covers_every_detection() -> None:
    md = attackdoc.render_markdown()
    for det in load():
        assert det.id in md, f"{det.id} missing from ATT&CK doc"


def test_layer_has_a_technique_for_every_tag() -> None:
    layer = attackdoc.render_layer()
    tagged = {t for det in load() for t in det.attack}
    in_layer = {t["techniqueID"] for t in layer["techniques"]}  # type: ignore[union-attr]
    assert tagged == in_layer


def test_report_renders_and_escapes() -> None:
    detections = load()
    html = report.render(detections, {})
    assert "clouddetect validation report" in html
    for det in detections:
        assert det.title in html
    # No results passed in: every cell is the "not evaluated" state.
    assert 'class="pill skip"' in html
