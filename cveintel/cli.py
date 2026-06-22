"""Command-line interface for cveintel.

Subcommands:
    rank    - ranked, explained priority list
    enrich  - merge KEV/EPSS/CVSS signals onto records
    kev     - filter to KEV-listed CVEs only
    diff    - posture drift between two scan snapshots (early warning)
    feeds   - manage the edge/air-gap data-feed cache (cisa-kev/epss/nvd-cve)

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
        feeds=getattr(args, "feeds", False),
        offline=getattr(args, "offline", False),
        vulndb=getattr(args, "vulndb", False),
    )


def cmd_rank(args) -> int:
    enriched = _load_and_enrich(args)
    scored = rank_records(enriched)

    if getattr(args, "sarif", False):
        from .sarif import to_sarif

        print(json.dumps(to_sarif(scored), indent=2))
    elif args.json:
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


_DRIFT_GLYPH = {
    "kev_added": "KEV+",
    "kev_removed": "KEV-",
    "tier_up": "TIER^",
    "tier_down": "tier_v",
    "epss_spike": "EPSS^",
    "epss_drop": "epss_v",
    "cvss_up": "CVSS^",
    "cvss_down": "cvss_v",
    "appeared": "NEW",
    "resolved": "GONE",
}


def _print_drift(items, summary, show_notes: bool = True) -> None:
    if not items:
        print("(no posture drift between snapshots)")
        return

    print(
        f"{'CVE':<18} {'CHANGE':<24} {'WAS':>10}  {'NOW':>10}"
    )
    print("-" * 70)
    for it in items:
        kinds = ",".join(_DRIFT_GLYPH.get(k, k) for k in it.kinds)
        was = "-" if not it.before else f"{it.before['tier']}/{it.before['score']:.0f}"
        now = "-" if not it.after else f"{it.after['tier']}/{it.after['score']:.0f}"
        flag = "!" if it.worsened else " "
        print(f"{it.cve_id:<18} {kinds:<24} {was:>10}  {now:>10} {flag}")
        if show_notes:
            for n in it.notes:
                print(f"    - {n}")

    print(
        f"\n{summary['total_changed']} changed "
        f"({summary['worsened']} worsened): "
        f"KEV+{summary['kev_added']} TIER^{summary['tier_up']} "
        f"EPSS^{summary['epss_spike']} NEW{summary['appeared']} "
        f"GONE{summary['resolved']}"
    )


def cmd_diff(args) -> int:
    """Diff two scan snapshots and report (and optionally gate on) drift."""
    from .drift import diff_records, summarize

    fixtures = _resolve_fixtures(args.fixtures)

    def _enrich(path):
        from .enrich import enrich_records, load_cve_input

        recs = load_cve_input(path)
        return enrich_records(
            recs,
            fixtures_dir=fixtures,
            live=args.live,
            live_timeout=args.live_timeout,
            feeds=getattr(args, "feeds", False),
            offline=getattr(args, "offline", False),
        )

    before = _enrich(args.before)
    after = _enrich(args.after)

    items = diff_records(before, after, worsened_only=args.worsened_only)
    summary = summarize(items)

    if args.json:
        print(
            json.dumps(
                {"summary": summary, "drift": [it.to_dict() for it in items]},
                indent=2,
            )
        )
    else:
        _print_drift(items, summary, show_notes=not args.no_reasons)

    # Gate: any worsened drift trips the gate when --fail-on-drift is set.
    if args.fail_on_drift and summary["worsened"] > 0:
        if not args.json:
            print(
                f"\nFAIL: {summary['worsened']} CVE(s) worsened since the "
                f"prior snapshot",
                file=sys.stderr,
            )
        return EXIT_GATE
    return EXIT_OK


def cmd_feeds(args) -> int:
    """Manage the edge/air-gap feed cache restricted to cveintel's feeds."""
    from . import datafeeds, feeds as feeds_mod

    action = args.feeds_action

    if action == "list":
        rows = feeds_mod.list_feeds()
        if args.json:
            for f in rows:
                f["cached_age_hours"] = datafeeds.cached_age_hours(f["id"])
            print(json.dumps(rows, indent=2))
            return EXIT_OK
        print(f"{'FEED':<12} {'DOMAIN':<7} {'CACHE':<12} SOURCE")
        print("-" * 64)
        for f in rows:
            age = datafeeds.cached_age_hours(f["id"])
            cache = "uncached" if age is None else f"{age:.1f}h old"
            print(f"{f['id']:<12} {f.get('domain',''):<7} {cache:<12} {f['name']}")
            print(f"             {f['url']}")
        return EXIT_OK

    if action == "update":
        ids = args.ids or feeds_mod.RELEVANT_FEED_IDS
        for fid in ids:
            try:
                pth = feeds_mod.update(fid)
                print(f"  updated {fid} -> {pth} ({pth.stat().st_size} bytes)")
            except (KeyError, ConnectionError) as e:
                print(f"  {fid}: {e}", file=sys.stderr)
                return EXIT_ERROR
        return EXIT_OK

    if action == "get":
        try:
            data = feeds_mod.get(args.id, offline=args.offline)
        except (KeyError, FileNotFoundError, ConnectionError) as e:
            print(f"error: {e}", file=sys.stderr)
            return EXIT_ERROR
        text = json.dumps(data, indent=2) if isinstance(data, (dict, list)) else str(data)
        print(text[:4000])
        return EXIT_OK

    if action == "snapshot-export":
        n = datafeeds.snapshot_export(args.path)
        print(f"exported {n} feed(s) -> {args.path}")
        return EXIT_OK

    if action == "snapshot-import":
        n = datafeeds.snapshot_import(args.path)
        print(f"imported snapshot from {args.path} ({n} feed(s) now cached)")
        return EXIT_OK

    return EXIT_ERROR


def cmd_sbom(args) -> int:
    """PASSIVE: match an SBOM / package list to CVEs in the offline corpus.

    No network. Reads only the provided SBOM and the bundled vuln DB.
    """
    from .vulnmatch import load_sbom, scan_sbom

    packages = load_sbom(args.input)
    records = scan_sbom(packages, ecosystem_strict=args.ecosystem_strict)
    scored = rank_records(records)

    if getattr(args, "sarif", False):
        from .sarif import to_sarif

        print(json.dumps(to_sarif(scored), indent=2))
    elif args.json:
        print(json.dumps([s.to_dict() for s in scored], indent=2))
    else:
        print(
            f"SBOM passive scan: {len(packages)} package(s) -> "
            f"{len(scored)} CVE(s) (offline corpus)"
        )
        _print_table(scored, show_reasons=not args.no_reasons)

    if _gate_triggered(scored, args.fail_on):
        if not args.json:
            print(
                f"\nFAIL: at least one CVE meets --fail-on {args.fail_on.upper()}",
                file=sys.stderr,
            )
        return EXIT_GATE
    return EXIT_OK


def cmd_active(args) -> int:
    """ACTIVE (authorization-gated): read-only banner/header probe.

    AUTHORIZED USE ONLY. Off by default; requires --authorized, a non-empty
    --target-allowlist, and a positive --rate-limit. Out-of-scope targets are
    refused. Sends no exploits - only reads response headers and maps disclosed
    banners to the offline corpus.
    """
    from .active import AUTHORIZED_USE_BANNER, ActiveProbe, ScopeError

    print(AUTHORIZED_USE_BANNER, file=sys.stderr)

    try:
        probe = ActiveProbe(
            allowlist=args.target_allowlist or [],
            authorized=args.authorized,
            rate_limit=args.rate_limit,
            timeout=args.timeout,
        )
    except (PermissionError, ScopeError, ValueError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return EXIT_ERROR

    results, findings = probe.scan(args.targets, skip_out_of_scope=True)
    scored = rank_records(findings)

    if args.json:
        print(
            json.dumps(
                {
                    "probes": [r.to_dict() for r in results],
                    "findings": [s.to_dict() for s in scored],
                },
                indent=2,
            )
        )
    else:
        for r in results:
            if r.error:
                print(f"{r.target}: {r.error}")
            else:
                print(f"{r.target}: HTTP {r.status}; banners: {r.banners or '-'}")
        print()
        print(
            f"Active probe: {len(results)} target(s) -> "
            f"{len(scored)} CVE finding(s) from disclosed banners"
        )
        _print_table(scored, show_reasons=not args.no_reasons)

    if _gate_triggered(scored, args.fail_on):
        if not args.json:
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
        sp.add_argument(
            "--feeds",
            action="store_true",
            help="enrich from the edge/air-gap data-feed cache "
            "(cisa-kev/epss/nvd-cve); refreshes from network unless --offline",
        )
        sp.add_argument(
            "--offline",
            action="store_true",
            help="with --feeds, serve signals from the local feed cache only "
            "(no network) - for air-gapped / disconnected operation",
        )
        sp.add_argument(
            "--vulndb",
            action="store_true",
            help="passively fill missing CVSS from the bundled offline vuln DB "
            "(~262k records; no network)",
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
    sp_rank.add_argument(
        "--sarif",
        action="store_true",
        help="emit a SARIF 2.1.0 log (for GitHub code-scanning / dashboards)",
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

    sp_diff = sub.add_parser(
        "diff",
        help="posture drift between two scan snapshots (KEV/tier/EPSS/CVSS)",
    )
    sp_diff.add_argument("before", help="prior snapshot CVE input JSON")
    sp_diff.add_argument("after", help="current snapshot CVE input JSON")
    sp_diff.add_argument(
        "--fixtures",
        default=None,
        help="signal-source directory (kev.json/epss.json/nvd.json) for both "
        "snapshots (default: bundled examples/)",
    )
    sp_diff.add_argument(
        "--live", action="store_true", help="fetch signals live (network)"
    )
    sp_diff.add_argument("--live-timeout", type=float, default=20.0)
    sp_diff.add_argument(
        "--feeds",
        action="store_true",
        help="enrich both snapshots from the edge/air-gap feed cache",
    )
    sp_diff.add_argument(
        "--offline",
        action="store_true",
        help="with --feeds, serve from local cache only (air-gapped)",
    )
    sp_diff.add_argument(
        "--worsened-only",
        action="store_true",
        help="show only changes that make the posture worse",
    )
    sp_diff.add_argument(
        "--no-reasons", action="store_true", help="hide per-CVE drift notes"
    )
    sp_diff.add_argument("--json", action="store_true", help="emit JSON")
    sp_diff.add_argument(
        "--fail-on-drift",
        action="store_true",
        help="exit non-zero (2) if any CVE worsened since the prior snapshot "
        "(CI early-warning gate)",
    )
    sp_diff.set_defaults(func=cmd_diff)

    sp_feeds = sub.add_parser(
        "feeds",
        help="manage the edge/air-gap data-feed cache (cisa-kev/epss/nvd-cve)",
    )
    sp_feeds.add_argument("--json", action="store_true", help="emit JSON")
    fsub = sp_feeds.add_subparsers(dest="feeds_action", required=True)
    fsub.add_parser("list", help="list cveintel's feeds + cache freshness")
    fu = fsub.add_parser("update", help="fetch + cache feeds (network)")
    fu.add_argument(
        "ids", nargs="*", help="feed ids (default: all of cisa-kev/epss/nvd-cve)"
    )
    fg = fsub.add_parser("get", help="print a cached/fetched feed")
    fg.add_argument("id", help="feed id (cisa-kev/epss/nvd-cve)")
    fg.add_argument(
        "--offline", action="store_true", help="serve from cache only (no network)"
    )
    fe = fsub.add_parser(
        "snapshot-export", help="tar the feed cache for air-gap sneakernet"
    )
    fe.add_argument("path", help="output .tar.gz path")
    fi = fsub.add_parser(
        "snapshot-import", help="rehydrate the feed cache from a snapshot"
    )
    fi.add_argument("path", help="input .tar.gz path")
    sp_feeds.set_defaults(func=cmd_feeds)

    # PASSIVE: SBOM / package-list scan against the bundled offline corpus.
    sp_sbom = sub.add_parser(
        "sbom",
        help="PASSIVE: match an SBOM/package list to CVEs (offline corpus, no network)",
    )
    sp_sbom.add_argument(
        "input",
        help="SBOM path (JSON list of names, CycloneDX, or newline-delimited names)",
    )
    sp_sbom.add_argument(
        "--ecosystem-strict",
        action="store_true",
        help="only match within the package's declared ecosystem",
    )
    sp_sbom.add_argument(
        "--no-reasons", action="store_true", help="hide per-CVE reason lines"
    )
    sp_sbom.add_argument(
        "--sarif", action="store_true", help="emit a SARIF 2.1.0 log"
    )
    sp_sbom.add_argument("--json", action="store_true", help="emit JSON")
    sp_sbom.add_argument(
        "--fail-on",
        choices=["critical", "high"],
        default=None,
        help="exit non-zero (2) if any CVE meets this tier (CI gate)",
    )
    sp_sbom.set_defaults(func=cmd_sbom)

    # ACTIVE: authorization-gated, read-only banner probe (OFF by default).
    sp_active = sub.add_parser(
        "active",
        help="ACTIVE (AUTHORIZED USE ONLY): read-only banner/header probe of "
        "consented, in-scope targets; OFF by default",
    )
    sp_active.add_argument("targets", nargs="+", help="target URL(s) to probe")
    sp_active.add_argument(
        "--authorized",
        action="store_true",
        help="REQUIRED. Affirm you have explicit written authorization to "
        "test these targets. Without it, active mode refuses to run.",
    )
    sp_active.add_argument(
        "--target-allowlist",
        action="append",
        default=[],
        metavar="HOST",
        help="REQUIRED. In-scope host (repeatable). Supports *.example.com. "
        "Targets whose host is not listed are refused, never probed.",
    )
    sp_active.add_argument(
        "--rate-limit",
        type=float,
        default=1.0,
        help="max requests/second (must be > 0; default 1.0)",
    )
    sp_active.add_argument(
        "--timeout", type=float, default=10.0, help="per-request timeout (s)"
    )
    sp_active.add_argument(
        "--no-reasons", action="store_true", help="hide per-CVE reason lines"
    )
    sp_active.add_argument("--json", action="store_true", help="emit JSON")
    sp_active.add_argument(
        "--fail-on",
        choices=["critical", "high"],
        default=None,
        help="exit non-zero (2) if any CVE meets this tier (CI gate)",
    )
    sp_active.set_defaults(func=cmd_active)

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
