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
from pathlib import Path

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


def _cmd_report(args: argparse.Namespace) -> int:  # pragma: no cover - live engines
    from clouddetect.engine import Engine, OpenSearchEngine, SplunkEngine
    from clouddetect.harness import evaluate
    from clouddetect.report import CellResult, Results, render

    detections = load()
    engines: tuple[Engine, ...] = (SplunkEngine(), OpenSearchEngine())
    results: Results = {}
    for engine in engines:
        try:
            engine.wait_ready()
        except Exception as exc:  # engine unreachable: every cell is "not evaluated"
            print(f"warning: {engine.name} not reachable ({exc}); skipping", file=sys.stderr)
            continue
        for det in detections:
            for fx in det.fixtures:
                verdict = evaluate(det, fx, engine)
                results[det.id, engine.name, fx.name] = CellResult(verdict.passed, verdict.detail)
    args.out.write_text(render(detections, results), encoding="utf-8")
    failed = sum(1 for r in results.values() if r.passed is False)
    print(f"wrote {args.out} ({len(results)} cells, {failed} failed)")
    return 1 if failed else 0


def _cmd_attack(args: argparse.Namespace) -> int:
    from clouddetect import attackdoc

    if args.layer is not None:
        import json

        args.layer.write_text(
            json.dumps(attackdoc.render_layer(), indent=2) + "\n", encoding="utf-8"
        )
        print(f"wrote {args.layer}")
    else:
        print(attackdoc.render_markdown(), end="")
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

    rep = sub.add_parser("report", help="replay through both engines and write an HTML report")
    rep.add_argument("--out", type=Path, default=Path("report.html"))
    rep.set_defaults(func=_cmd_report)

    atk = sub.add_parser("attack", help="print the ATT&CK doc, or write the Navigator layer")
    atk.add_argument("--layer", type=Path, help="write the Navigator layer JSON here")
    atk.set_defaults(func=_cmd_attack)

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
