"""The converter fails loudly on input it cannot turn into exactly one query."""

from __future__ import annotations

import pytest

from clouddetect import sigma

_TWO_RULES = """\
title: One
logsource: {product: aws, service: cloudtrail}
detection:
  sel:
    eventName: StopLogging
  condition: sel
---
title: Two
logsource: {product: aws, service: cloudtrail}
detection:
  sel:
    eventName: DeleteTrail
  condition: sel
"""


def test_garbage_is_a_conversion_error() -> None:
    with pytest.raises(sigma.ConversionError):
        sigma.to_spl("this is not: [a sigma rule")


def test_multiple_rules_rejected() -> None:
    with pytest.raises(sigma.ConversionError, match="exactly one"):
        sigma.to_spl(_TWO_RULES)
