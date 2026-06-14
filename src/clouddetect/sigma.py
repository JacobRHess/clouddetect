"""Convert one Sigma rule into the query each backend runs.

Detections are authored once as Sigma so the logic is portable and standard.
This module is the proof that the portability is real: the same rule is
converted to Splunk SPL and to an OpenSearch Lucene query, and CI replays both.
A rule that only converts cleanly to one backend is a rule with a portability
bug, and that is exactly what we want to surface.

The conversions are deliberately field-faithful. Fixtures are stored as raw
CloudTrail records and raw Okta System Log events, and the rules reference those
same field names (`eventName`, `userIdentity.type`, `outcome.result`, ...), so
no field-renaming pipeline sits between the rule and the data. The engine scopes
each search to a private per-run index; the converter only ever emits the match
logic, never an index selector.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache

from sigma.backends.elasticsearch import LuceneBackend  # type: ignore[attr-defined]
from sigma.backends.splunk import SplunkBackend  # type: ignore[attr-defined]
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule


class ConversionError(ValueError):
    """A Sigma rule could not be converted to a backend query."""


def _collection(rule_text: str) -> SigmaCollection:
    try:
        return SigmaCollection.from_yaml(rule_text)
    except Exception as exc:  # pySigma raises a family of parse errors
        raise ConversionError(f"rule did not parse as Sigma: {exc}") from exc


def _single(queries: list[str], backend: str) -> str:
    if not queries:
        raise ConversionError(f"{backend} backend produced no query")
    if len(queries) > 1:
        raise ConversionError(
            f"{backend} backend produced {len(queries)} queries; "
            "a clouddetect rule must convert to exactly one"
        )
    return str(queries[0])


@cache
def to_spl(rule_text: str) -> str:
    """Convert a Sigma rule to a Splunk SPL search expression (no index selector)."""
    return _single(SplunkBackend().convert(_collection(rule_text)), "splunk")


@cache
def to_lucene(rule_text: str) -> str:
    """Convert a Sigma rule to an OpenSearch/Lucene query string."""
    return _single(LuceneBackend().convert(_collection(rule_text)), "lucene")


@dataclass(frozen=True, slots=True)
class Correlation:
    """A count-over-time detection, in the form each engine needs.

    Splunk converts a Sigma correlation rule natively (the `spl` field is the
    full `... | bin | stats count by ... | search count >= N` search). The
    Lucene backend does not support correlation, so for OpenSearch we carry the
    base rule's filter plus the group-by field and threshold, and the engine
    runs a terms aggregation itself.
    """

    spl: str
    base_lucene: str
    group_by: str
    threshold: int


def is_correlation(rule_text: str) -> bool:
    return any(isinstance(r, SigmaCorrelationRule) for r in _collection(rule_text).rules)


def _base_only(rule_text: str) -> str:
    """The non-correlation YAML documents of a rule file, rejoined."""
    docs = [d for d in re.split(r"(?m)^---\s*$", rule_text) if d.strip()]
    base = [d for d in docs if "correlation:" not in d]
    if not base:
        raise ConversionError("correlation rule has no base detection document")
    return "\n---\n".join(base)


@cache
def correlation_spec(rule_text: str) -> Correlation:
    """Parse a correlation rule into a Splunk search and OpenSearch aggregation inputs."""
    coll = _collection(rule_text)
    corr = next((r for r in coll.rules if isinstance(r, SigmaCorrelationRule)), None)
    if corr is None:
        raise ConversionError("rule has no correlation block")
    if corr.type.name != "EVENT_COUNT":
        raise ConversionError(f"unsupported correlation type {corr.type.name!r}; only event_count")
    # The condition is a union of count/field-ref forms; only the simple
    # count comparison is supported here, so read op/count defensively.
    op = getattr(corr.condition, "op", None)
    count = getattr(corr.condition, "count", None)
    if op is None or count is None:
        raise ConversionError("unsupported correlation condition; only a count threshold")
    if op.name != "GTE":
        raise ConversionError(f"unsupported correlation condition {op.name!r}; only gte")
    if not corr.group_by:
        raise ConversionError("correlation rule needs exactly one group-by field")
    spl = _single(SplunkBackend().convert(coll), "splunk")
    base_lucene = _single(LuceneBackend().convert(_collection(_base_only(rule_text))), "lucene")
    return Correlation(
        spl=spl,
        base_lucene=base_lucene,
        group_by=corr.group_by[0],
        threshold=int(count),
    )
