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

from functools import cache

from sigma.backends.elasticsearch import LuceneBackend  # type: ignore[attr-defined]
from sigma.backends.splunk import SplunkBackend  # type: ignore[attr-defined]
from sigma.collection import SigmaCollection


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
