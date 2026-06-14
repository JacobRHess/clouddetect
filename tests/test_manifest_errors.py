"""Every manifest validation branch rejects what it should.

A manifest that silently accepts a bad entry is how a detection ends up never
firing with nobody noticing, so each guard has a test.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from clouddetect.manifest import ManifestError, load

RULE = "rules/cloudtrail/iam_attach_admin_policy.yml"
ALERT = "fixtures/cloudtrail/iam_attach_admin_policy.alert.json"
BENIGN = "fixtures/cloudtrail/iam_attach_admin_policy.benign.json"


def _valid_detection() -> dict[str, object]:
    return {
        "id": "d1",
        "title": "t",
        "logsource": "cloudtrail",
        "rule": RULE,
        "attack": ["T1098"],
        "fixtures": [
            {"events": ALERT, "expect": "alert"},
            {"events": BENIGN, "expect": "clean"},
        ],
    }


def _write(tmp_path: Path, doc: object) -> Path:
    path = tmp_path / "detections.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return path


def test_loads_a_valid_manifest(tmp_path: Path) -> None:
    assert load(_write(tmp_path, {"detections": [_valid_detection()]}))


def test_root_must_be_mapping(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="mapping"):
        load(_write(tmp_path, ["not", "a", "mapping"]))


def test_needs_at_least_one_detection(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="at least one detection"):
        load(_write(tmp_path, {"detections": []}))


def test_missing_required_key(tmp_path: Path) -> None:
    det = _valid_detection()
    del det["title"]
    with pytest.raises(ManifestError, match="missing required key"):
        load(_write(tmp_path, {"detections": [det]}))


def test_bad_logsource(tmp_path: Path) -> None:
    det = _valid_detection()
    det["logsource"] = "syslog"
    with pytest.raises(ManifestError, match="logsource must be"):
        load(_write(tmp_path, {"detections": [det]}))


def test_bad_expect(tmp_path: Path) -> None:
    det = _valid_detection()
    det["fixtures"] = [{"events": ALERT, "expect": "maybe"}]
    with pytest.raises(ManifestError, match="expect must be"):
        load(_write(tmp_path, {"detections": [det]}))


def test_path_escaping_repo_is_rejected(tmp_path: Path) -> None:
    det = _valid_detection()
    det["rule"] = "../../../etc/passwd"
    with pytest.raises(ManifestError, match=r"escapes the repository root|does not exist"):
        load(_write(tmp_path, {"detections": [det]}))


def test_nonexistent_file_is_rejected(tmp_path: Path) -> None:
    det = _valid_detection()
    det["rule"] = "rules/cloudtrail/does_not_exist.yml"
    with pytest.raises(ManifestError, match="does not exist"):
        load(_write(tmp_path, {"detections": [det]}))


def test_needs_both_alert_and_clean(tmp_path: Path) -> None:
    det = _valid_detection()
    det["fixtures"] = [{"events": ALERT, "expect": "alert"}]
    with pytest.raises(ManifestError, match=r"alert.*clean|clean.*alert"):
        load(_write(tmp_path, {"detections": [det]}))


def test_duplicate_ids_rejected(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="duplicate detection id"):
        load(_write(tmp_path, {"detections": [_valid_detection(), _valid_detection()]}))


def test_fixtures_must_be_a_non_empty_list(tmp_path: Path) -> None:
    det = _valid_detection()
    det["fixtures"] = {}
    with pytest.raises(ManifestError, match="non-empty list"):
        load(_write(tmp_path, {"detections": [det]}))


def test_missing_manifest_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="manifest not found"):
        load(tmp_path / "does_not_exist.yaml")
