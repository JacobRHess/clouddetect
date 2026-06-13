"""clouddetect command line.

`list` and `validate` need nothing but the repo: they read the manifest and run
the Sigma conversions, so they are the fast offline gate. Replaying fixtures
through live engines is `pytest -m replay`; reporting and the live AWS loop land
in their own subcommands.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from clouddetect import sigma
from clouddetect.manifest import Detection, ManifestError, load


def _cmd_list(_: argparse.Namespace) -> int:
    for det in load():
        attack = ", ".join(det.attack) or "-"
        print(f"{det.id}\n  {det.title}")
        print(f"  source: {det.logsource.value}   attack: {attack}")
        for fx in det.fixtures:
            print(f"    [{fx.expect.value:>5}] {fx.events.name}")
    return 0


def _convert_both(det: Detection) -> tuple[str, str]:
    rule = det.rule.read_text(encoding="utf-8")
    return sigma.to_spl(rule), sigma.to_lucene(rule)


def _cmd_validate(_: argparse.Namespace) -> int:
    detections = load()
    failures = 0
    for det in detections:
        try:
            _convert_both(det)
        except sigma.ConversionError as exc:
            failures += 1
            print(f"FAIL  {det.id}: {exc}", file=sys.stderr)
        else:
            print(f"ok    {det.id}")
    print(f"\n{len(detections) - failures}/{len(detections)} detections convert on both backends")
    return 1 if failures else 0


def _cmd_convert(args: argparse.Namespace) -> int:
    detections = {d.id: d for d in load()}
    det = detections.get(args.id)
    if det is None:
        print(f"no detection with id {args.id!r}", file=sys.stderr)
        return 2
    spl, lucene = _convert_both(det)
    if args.backend in ("splunk", "both"):
        print(f"# splunk (SPL)\n{spl}")
    if args.backend in ("opensearch", "both"):
        print(f"# opensearch (Lucene)\n{lucene}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="clouddetect", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list every detection and its ATT&CK mapping").set_defaults(
        func=_cmd_list
    )
    sub.add_parser(
        "validate", help="check every rule parses and converts on both backends"
    ).set_defaults(func=_cmd_validate)

    conv = sub.add_parser("convert", help="print the converted query for one detection")
    conv.add_argument("id", help="detection id")
    conv.add_argument("--backend", choices=("splunk", "opensearch", "both"), default="both")
    conv.set_defaults(func=_cmd_convert)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result: int = args.func(args)
    except ManifestError as exc:
        print(f"manifest error: {exc}", file=sys.stderr)
        return 2
    return result


if __name__ == "__main__":
    raise SystemExit(main())
