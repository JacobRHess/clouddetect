"""The pure parsing side of correlation rules: detection, SPL, and the inputs
the OpenSearch aggregation needs. The live behaviour is proven by the replay job.
"""

from __future__ import annotations

from clouddetect import sigma
from clouddetect.manifest import load


def _rule(detection_id: str) -> str:
    det = next(d for d in load() if d.id == detection_id)
    return det.rule.read_text(encoding="utf-8")


def test_is_correlation_distinguishes_rule_kinds() -> None:
    assert sigma.is_correlation(_rule("okta-mfa-fatigue"))
    assert not sigma.is_correlation(_rule("iam-attach-admin-policy"))


def test_correlation_spec_extracts_threshold_and_group() -> None:
    spec = sigma.correlation_spec(_rule("okta-mfa-fatigue"))
    assert spec.group_by == "actor.alternateId"
    assert spec.threshold == 5
    # Splunk gets the full windowed count search; OpenSearch gets the base filter.
    assert "stats count" in spec.spl
    assert "event_count >= 5" in spec.spl
    assert "deny_push" in spec.base_lucene
    assert "stats" not in spec.base_lucene  # base filter only, no aggregation


def test_correlation_spec_reads_each_rule() -> None:
    for det_id, group, threshold in [
        ("okta-login-brute-force", "actor.alternateId", 10),
        ("secretsmanager-retrieval-burst", "userIdentity.arn", 10),
    ]:
        spec = sigma.correlation_spec(_rule(det_id))
        assert spec.group_by == group
        assert spec.threshold == threshold
