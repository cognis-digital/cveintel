"""Offline tests for the edge/air-gap data-feed layer.

NO NETWORK. Every test points ``COGNIS_FEEDS_CACHE`` at the committed trimmed
fixture cache (tests/fixtures/feeds-cache/) and serves feeds with
``offline=True`` / ``--offline`` so CI stays green with zero egress.
"""

import json
import os

import pytest

from cveintel import datafeeds, feeds
from cveintel.cli import EXIT_ERROR, EXIT_OK, main

FIXTURE_CACHE = os.path.join(
    os.path.dirname(__file__), "fixtures", "feeds-cache"
)
DEMO = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "demos",
    "11-airgap-feeds-enrichment",
)
SCAN = os.path.join(DEMO, "scan.json")


@pytest.fixture(autouse=True)
def _point_cache_at_fixtures(monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", FIXTURE_CACHE)
    yield


# --------------------------------------------------------------------------- #
# catalog filtering
# --------------------------------------------------------------------------- #
def test_catalog_restricted_to_cveintel_feeds():
    ids = [f["id"] for f in feeds.list_feeds()]
    assert ids == ["cisa-kev", "epss", "nvd-cve"]


def test_relevant_feeds_are_real_keyless_vuln_sources():
    for f in feeds.list_feeds():
        assert f["domain"] == "vuln"
        assert f["keyless"] is True
        assert f["url"].startswith("https://")


def test_get_rejects_out_of_scope_feed():
    # feodo-c2 exists in the full catalog but is not a cveintel feed.
    with pytest.raises(KeyError):
        feeds.get("feodo-c2", offline=True)


# --------------------------------------------------------------------------- #
# offline signal extraction
# --------------------------------------------------------------------------- #
def test_signals_offline_from_cache():
    kev, epss, cvss = feeds.signals(
        ["CVE-2021-44228", "CVE-2023-34362", "CVE-2024-3400"], offline=True
    )
    assert {"CVE-2021-44228", "CVE-2023-34362", "CVE-2024-3400"} <= kev
    assert epss["CVE-2021-44228"] == pytest.approx(0.99999)
    assert cvss["CVE-2023-34362"] == pytest.approx(9.8)
    assert cvss["CVE-2024-3400"] == pytest.approx(10.0)


def test_offline_get_raises_when_uncached(tmp_path, monkeypatch):
    # Empty cache dir + offline -> FileNotFoundError, never a network call.
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    with pytest.raises(FileNotFoundError):
        feeds.get("cisa-kev", offline=True)


def test_kev_parser_handles_catalog_and_list_shapes():
    catalog = {"vulnerabilities": [{"cveID": "CVE-1"}, {"cveID": "CVE-2"}]}
    assert feeds.kev_set_from_feed(catalog) == {"CVE-1", "CVE-2"}
    assert feeds.kev_set_from_feed(["CVE-1"]) == {"CVE-1"}


def test_epss_parser_handles_api_and_map_shapes():
    api = {"data": [{"cve": "CVE-1", "epss": "0.5"}]}
    assert feeds.epss_map_from_feed(api) == {"CVE-1": 0.5}
    assert feeds.epss_map_from_feed({"CVE-2": 0.1}) == {"CVE-2": 0.1}


# --------------------------------------------------------------------------- #
# end-to-end enrichment via the feed cache (the real value-add)
# --------------------------------------------------------------------------- #
def test_rank_offline_via_feeds(capsys):
    rc = main(["rank", SCAN, "--feeds", "--offline", "--json"])
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    by_id = {r["cve_id"]: r for r in data}
    # All three KEV-listed, high-EPSS, high-CVSS CVEs land CRITICAL...
    for cid in ("CVE-2021-44228", "CVE-2023-34362", "CVE-2024-3400"):
        assert by_id[cid]["kev"] is True
        assert by_id[cid]["tier"] == "CRITICAL"
    # ...the non-KEV, low-EPSS one ranks last and is not CRITICAL.
    assert data[-1]["cve_id"] == "CVE-2024-99999"
    assert by_id["CVE-2024-99999"]["kev"] is False
    assert by_id["CVE-2024-99999"]["tier"] != "CRITICAL"
    # descending score order
    scores = [r["score"] for r in data]
    assert scores == sorted(scores, reverse=True)


def test_enrich_offline_fills_signals_from_feeds(capsys):
    rc = main(["enrich", SCAN, "--feeds", "--offline", "--json"])
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    by_id = {r["cve_id"]: r for r in data}
    assert by_id["CVE-2021-44228"]["cvss"] == 10.0
    assert by_id["CVE-2021-44228"]["epss"] == pytest.approx(0.99999)
    assert by_id["CVE-2021-44228"]["kev"] is True


# --------------------------------------------------------------------------- #
# CLI: feeds subcommand
# --------------------------------------------------------------------------- #
def test_feeds_list_json(capsys):
    rc = main(["feeds", "--json", "list"])
    assert rc == EXIT_OK
    rows = json.loads(capsys.readouterr().out)
    assert {r["id"] for r in rows} == {"cisa-kev", "epss", "nvd-cve"}
    # cache freshness surfaced from the committed fixture cache
    assert all(r["cached_age_hours"] is not None for r in rows)


def test_feeds_get_offline(capsys):
    rc = main(["feeds", "get", "cisa-kev", "--offline"])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "CVE-2021-44228" in out


def test_feeds_get_unknown_id_errors(capsys):
    rc = main(["feeds", "get", "not-a-feed", "--offline"])
    assert rc == EXIT_ERROR


# --------------------------------------------------------------------------- #
# air-gap snapshot round-trip (sneakernet), fully offline
# --------------------------------------------------------------------------- #
def test_snapshot_export_import_roundtrip(tmp_path, monkeypatch):
    archive = tmp_path / "feeds.tar.gz"
    # export from the fixture cache
    n = datafeeds.snapshot_export(str(archive))
    assert n == 3
    assert archive.exists()
    # import into a fresh, empty cache dir
    dest = tmp_path / "enclave-cache"
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(dest))
    imported = datafeeds.snapshot_import(str(archive))
    assert imported == 3
    # and the rehydrated cache serves offline
    kev = feeds.kev_set_from_feed(feeds.get("cisa-kev", offline=True))
    assert "CVE-2021-44228" in kev
