"""The offline CLI commands: list, validate, convert, attack.

The report command drives live engines and is covered by the replay job, not
here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clouddetect.cli import main
from clouddetect.manifest import load


def test_list_names_every_detection(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    for det in load():
        assert det.id in out


def test_validate_passes(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validate"]) == 0
    assert "convert on both backends" in capsys.readouterr().out


def test_convert_prints_both_backends(capsys: pytest.CaptureFixture[str]) -> None:
    det_id = load()[0].id
    assert main(["convert", det_id]) == 0
    out = capsys.readouterr().out
    assert "# splunk (SPL)" in out
    assert "# opensearch (Lucene)" in out


def test_convert_single_backend(capsys: pytest.CaptureFixture[str]) -> None:
    det_id = load()[0].id
    assert main(["convert", det_id, "--backend", "splunk"]) == 0
    out = capsys.readouterr().out
    assert "# splunk (SPL)" in out
    assert "Lucene" not in out


def test_convert_unknown_id_returns_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["convert", "no-such-detection"]) == 2
    assert "no detection with id" in capsys.readouterr().err


def test_attack_prints_markdown(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["attack"]) == 0
    assert "# ATT&CK coverage" in capsys.readouterr().out


def test_attack_writes_layer(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "layer.json"
    assert main(["attack", "--layer", str(out)]) == 0
    layer = json.loads(out.read_text(encoding="utf-8"))
    assert layer["domain"] == "enterprise-attack"
    assert layer["techniques"]
