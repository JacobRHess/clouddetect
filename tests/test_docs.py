"""The ATT&CK doc and the HTML report are generated faithfully from the manifest.

The CI drift check is the real guard on docs/ATTACK.md; these tests catch the
common breakages earlier and offline: a technique with no name on file, a
manifest tag that never reaches the layer, an unescaped value in the report.
"""

from __future__ import annotations

import pytest

from clouddetect import attackdoc, report
from clouddetect.manifest import Detection, LogSource, load


def test_markdown_covers_every_detection() -> None:
    md = attackdoc.render_markdown()
    for det in load():
        assert det.id in md, f"{det.id} missing from ATT&CK doc"


def test_layer_has_a_technique_for_every_tag() -> None:
    layer = attackdoc.render_layer()
    tagged = {t for det in load() for t in det.attack}
    in_layer = {t["techniqueID"] for t in layer["techniques"]}  # type: ignore[union-attr]
    assert tagged == in_layer


def test_report_renders_skip_state_with_no_results() -> None:
    detections = load()
    html = report.render(detections, {})
    assert "clouddetect validation report" in html
    for det in detections:
        assert det.title in html
    # No results passed in: every cell is the "not evaluated" state.
    assert 'class="pill skip"' in html


def test_report_shows_pass_and_fail_and_escapes() -> None:
    det = load()[0]
    fixtures = {f.expect.value: f for f in det.fixtures}
    results: report.Results = {
        (det.id, "splunk", fixtures["alert"].name): report.CellResult(True, "fired"),
        # A failing cell whose detail carries HTML that must be escaped.
        (det.id, "opensearch", fixtures["clean"].name): report.CellResult(
            False, 'fired on <script>alert("x")</script> & broke'
        ),
    }
    html = report.render((det,), results)
    assert ">PASS<" in html
    assert ">FAIL<" in html
    # The dangerous detail is escaped, never emitted raw.
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_check_names_raises_on_unmapped_technique(monkeypatch: pytest.MonkeyPatch) -> None:
    real = load()[0]
    bogus = Detection(
        id="bogus",
        title="bogus",
        logsource=LogSource.CLOUDTRAIL,
        rule=real.rule,
        attack=("T9999",),
        fixtures=real.fixtures,
    )
    monkeypatch.setattr(attackdoc, "load", lambda: (bogus,))
    with pytest.raises(ValueError, match="no ATT&CK name"):
        attackdoc.render_markdown()
