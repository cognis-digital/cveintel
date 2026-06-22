"""Verify every shipped demo actually produces its intended finding.

Each demo folder under ``demos/`` carries a real-input ``scan.json`` plus its
own fixtures. These tests run the CLI against each demo exactly as the
SCENARIO.md instructs and assert the documented outcome, so a demo can never
silently rot into producing nothing.
"""

import json
import os

import pytest

from cveintel.cli import EXIT_GATE, EXIT_OK, main

DEMOS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "demos")


def _rank_json(demo):
    d = os.path.join(DEMOS, demo)
    rc = main(["rank", os.path.join(d, "scan.json"), "--fixtures", d, "--json"])
    return rc, d


def _load(capsys):
    return json.loads(capsys.readouterr().out)


def test_all_demo_folders_have_required_files():
    folders = [f for f in os.listdir(DEMOS) if os.path.isdir(os.path.join(DEMOS, f))]
    assert len(folders) >= 8
    for f in folders:
        d = os.path.join(DEMOS, f)
        # A demo carries either a single-scan input (scan.json) or, for the
        # posture-drift demo, a before/after pair.
        has_scan = os.path.exists(os.path.join(d, "scan.json"))
        has_pair = os.path.exists(os.path.join(d, "before.json")) and os.path.exists(
            os.path.join(d, "after.json")
        )
        assert has_scan or has_pair, f"{f} missing scan.json (or before/after pair)"
        assert os.path.exists(os.path.join(d, "SCENARIO.md")), f"{f} missing SCENARIO.md"


@pytest.mark.parametrize(
    "demo,top_cve,top_tier",
    [
        ("01-log4shell-incident", "CVE-2021-44228", "CRITICAL"),
        ("02-edge-appliance-exposure", "CVE-2018-13379", "CRITICAL"),
        ("03-moveit-supply-chain", "CVE-2023-34362", "CRITICAL"),
        ("04-exchange-proxyshell", "CVE-2021-26855", "CRITICAL"),
        ("06-scanner-noise-deprioritize", "CVE-2021-44228", "CRITICAL"),
        ("07-monthly-kev-review", "CVE-2017-5638", "CRITICAL"),
        ("09-mixed-vendor-patch-tuesday", "CVE-2024-1709", "CRITICAL"),
        ("10-internet-facing-asset-blast", "CVE-2024-1709", "CRITICAL"),
    ],
)
def test_demo_top_finding(demo, top_cve, top_tier, capsys):
    rc, _ = _rank_json(demo)
    assert rc == EXIT_OK
    data = _load(capsys)
    assert data, f"{demo} produced no findings"
    # descending score
    scores = [r["score"] for r in data]
    assert scores == sorted(scores, reverse=True)
    assert data[0]["cve_id"] == top_cve
    assert data[0]["tier"] == top_tier


def test_demo06_high_cvss_but_quiet_stays_med(capsys):
    # CVSS 9.8 OpenSSL bug must NOT outrank Log4Shell and must land in MED
    _rank_json("06-scanner-noise-deprioritize")
    data = _load(capsys)
    by_id = {r["cve_id"]: r for r in data}
    assert by_id["CVE-2021-3711"]["cvss"] == 9.8
    assert by_id["CVE-2021-3711"]["tier"] == "MED"
    assert by_id["CVE-2021-44228"]["score"] > by_id["CVE-2021-3711"]["score"]


def test_demo05_release_gate_blocks_on_high():
    d = os.path.join(DEMOS, "05-ci-release-gate")
    rc = main(
        ["rank", os.path.join(d, "scan.json"), "--fixtures", d, "--fail-on", "high"]
    )
    assert rc == EXIT_GATE


def test_demo08_zero_signal_is_low_not_fabricated(capsys):
    d = os.path.join(DEMOS, "08-bare-cve-ids-baseline")
    rc = main(["rank", os.path.join(d, "scan.json"), "--fixtures", d, "--json"])
    assert rc == EXIT_OK
    data = _load(capsys)
    for r in data:
        assert r["cvss"] is None
        assert r["epss"] is None
        assert r["kev"] is False
        assert r["score"] == 0.0
        assert r["tier"] == "LOW"


def test_demo03_kev_promotion_and_input_cvss_preserved(capsys):
    d = os.path.join(DEMOS, "03-moveit-supply-chain")
    rc = main(["enrich", os.path.join(d, "scan.json"), "--fixtures", d, "--json"])
    assert rc == EXIT_OK
    data = _load(capsys)
    by_id = {r["cve_id"]: r for r in data}
    # input CVSS preserved (no nvd.json in this demo)
    assert by_id["CVE-2023-34362"]["cvss"] == 9.8
    # catalog promotes this one to KEV...
    assert by_id["CVE-2023-35708"]["kev"] is True
    # ...but the non-KEV follow-up stays false
    assert by_id["CVE-2023-35036"]["kev"] is False


def test_demo12_posture_drift_reports_kev_escalations(capsys):
    d = os.path.join(DEMOS, "12-posture-drift-early-warning")
    rc = main(
        [
            "diff",
            os.path.join(d, "before.json"),
            os.path.join(d, "after.json"),
            "--fixtures",
            d,
            "--json",
        ]
    )
    assert rc == EXIT_OK
    data = _load(capsys)
    summary = data["summary"]
    # five edge appliances newly KEV-listed; one decommissioned (MOVEit).
    assert summary["kev_added"] == 5
    assert summary["resolved"] == 1
    assert summary["appeared"] == 1  # ScreenConnect newly in scope
    drift = {x["cve_id"]: x for x in data["drift"]}
    # Citrix Bleed flipped MED -> CRITICAL with KEV + EPSS spike.
    citrix = drift["CVE-2023-4966"]
    assert {"kev_added", "tier_up", "epss_spike"} <= set(citrix["kinds"])
    # MOVEit dropped out of scope.
    assert drift["CVE-2023-34362"]["kinds"] == ["resolved"]


def test_demo12_drift_gate_trips(capsys):
    d = os.path.join(DEMOS, "12-posture-drift-early-warning")
    rc = main(
        [
            "diff",
            os.path.join(d, "before.json"),
            os.path.join(d, "after.json"),
            "--fixtures",
            d,
            "--worsened-only",
            "--fail-on-drift",
        ]
    )
    assert rc == EXIT_GATE


def test_demo10_asset_metadata_survives_enrichment(capsys):
    d = os.path.join(DEMOS, "10-internet-facing-asset-blast")
    rc = main(["enrich", os.path.join(d, "scan.json"), "--fixtures", d, "--json"])
    assert rc == EXIT_OK
    data = _load(capsys)
    by_id = {r["cve_id"]: r for r in data}
    assert by_id["CVE-2024-1709"]["exposure"] == "internet"
    assert "asset" in by_id["CVE-2024-1709"]
