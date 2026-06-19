"""Command-line interface for cveintel.

Subcommands:
    rank    - ranked, explained priority list
    enrich  - merge KEV/EPSS/CVSS signals onto records
    kev     - filter to KEV-listed CVEs only

Standard library only (argparse).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import __version__
from .enrich import default_fixtures_dir, enrich_records, filter_kev, load_cve_input
from .scoring import TIER_ORDER, rank_records, score_record

EXIT_OK = 0
EXIT_GATE = 2   # --fail-on threshold met
EXIT_ERROR = 1  # usage / IO error


def _resolve_fixtures(arg: Optional[str]) -> str:
    if arg:
        return arg
    found = default_fixtures_dir()
    if found:
        return found
    # Fall back to cwd/examples; load_* functions tolerate missing files.
    return "examples"


def _fmt_score(s: float) -> str:
    return f"{s:5.1f}"


def _fmt_cell(value, width: int) -> str:
    text = "-" if value is None else str(value)
    return text.ljust(width)


def _print_table(scored, show_reasons: bool = True) -> None:
    if not scored:
        print("(no CVEs)")
        return

    print(f"{'CVE':<18} {'TIER':<9} {'SCORE':>6} {'CVSS':>5} {'EPSS':>6} {'KEV':>4}")
    print("-" * 56)
    for s in scored:
        cvss = "-" if s.cvss is None else f"{s.cvss:.1f}"
        epss = "-" if s.epss is None else f"{s.epss:.2f}"
        kev = "yes" if s.kev else "-"
        print(
            f"{s.cve_id:<18} {s.tier:<9} {_fmt_score(s.score)} "
            f"{cvss:>5} {epss:>6} {kev:>4}"
        )
        if show_reasons:
            for r in s.reasons:
                print(f"    - {r}")


def _gate_triggered(scored, fail_on: Optional[str]) -> bool:
    if not fail_on:
        return False
    threshold = TIER_ORDER[fail_on.upper()]
    return any(TIER_ORDER[s.tier] >= threshold for s in scored)


def _load_and_enrich(args) -> list[dict]:
    records = load_cve_input(args.input)
    fixtures = _resolve_fixtures(args.fixtures)
    return enrich_records(
        records,
        fixtures_dir=fixtures,
        live=args.live,
        live_timeout=args.live_timeout,
    )


def cmd_rank(args) -> int:
    enriched = _load_and_enrich(args)
    scored = rank_records(enriched)

    if args.json:
        print(json.dumps([s.to_dict() for s in scored], indent=2))
    else:
        _print_table(scored, show_reasons=not args.no_reasons)

    if _gate_triggered(scored, args.fail_on):
        if not args.json:
            print(
                f"\nFAIL: at least one CVE meets --fail-on {args.fail_on.upper()}",
                file=sys.stderr,
            )
        return EXIT_GATE
    return EXIT_OK


def cmd_enrich(args) -> int:
    enriched = _load_and_enrich(args)

    if args.json:
        print(json.dumps(enriched, indent=2))
    else:
        scored = [score_record(r) for r in enriched]
        _print_table(scored, show_reasons=False)

    if args.fail_on:
        scored = [score_record(r) for r in enriched]
        if _gate_triggered(scored, args.fail_on):
            print(
                f"\nFAIL: at least one CVE meets --fail-on {args.fail_on.upper()}",
                file=sys.stderr,
            )
            return EXIT_GATE
    return EXIT_OK


def cmd_kev(args) -> int:
    enriched = _load_and_enrich(args)
    kev_only = filter_kev(enriched)

    if args.json:
        print(json.dumps(kev_only, indent=2))
    else:
        scored = rank_records(kev_only)
        _print_table(scored, show_reasons=not args.no_reasons)
        if not kev_only:
            print("(no KEV-listed CVEs in input)")

    if _gate_triggered(rank_records(kev_only), args.fail_on):
        print(
            f"\nFAIL: at least one CVE meets --fail-on {args.fail_on.upper()}",
            file=sys.stderr,
        )
        return EXIT_GATE
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cveintel",
        description=(
            "Correlate CVSS, CISA KEV, and EPSS into an explained CVE "
            "priority ranking. Offline by default."
        ),
    )
    p.add_argument("--version", action="version", version=f"cveintel {__version__}")

    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp):
        sp.add_argument("input", help="path to CVE input JSON (ids or records)")
        sp.add_argument(
            "--fixtures",
            default=None,
            help="directory holding kev.json / epss.json / nvd.json "
            "(default: bundled examples/)",
        )
        sp.add_argument(
            "--live",
            action="store_true",
            help="fetch signals live from NVD / CISA KEV / EPSS (network)",
        )
        sp.add_argument(
            "--live-timeout",
            type=float,
            default=20.0,
            help="per-request timeout in seconds for --live (default: 20)",
        )
        sp.add_argument("--json", action="store_true", help="emit JSON instead of a table")
        sp.add_argument(
            "--fail-on",
            choices=["critical", "high"],
            default=None,
            help="exit non-zero (2) if any CVE meets this tier (CI gate)",
        )

    sp_rank = sub.add_parser("rank", help="ranked, explained priority list")
    add_common(sp_rank)
    sp_rank.add_argument(
        "--no-reasons", action="store_true", help="hide per-CVE reason lines"
    )
    sp_rank.set_defaults(func=cmd_rank)

    sp_enrich = sub.add_parser("enrich", help="merge KEV/EPSS/CVSS onto records")
    add_common(sp_enrich)
    sp_enrich.set_defaults(func=cmd_enrich)

    sp_kev = sub.add_parser("kev", help="filter to KEV-listed CVEs only")
    add_common(sp_kev)
    sp_kev.add_argument(
        "--no-reasons", action="store_true", help="hide per-CVE reason lines"
    )
    sp_kev.set_defaults(func=cmd_kev)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # `--no-reasons` only exists on rank/kev; default it for enrich.
    if not hasattr(args, "no_reasons"):
        args.no_reasons = True
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: file not found: {exc.filename}", file=sys.stderr)
        return EXIT_ERROR
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
