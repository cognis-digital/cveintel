"""Tests for offline enrichment: signal merge, KEV filter, input parsing."""

import json
import os

import pytest

from cveintel.enrich import (
    enrich_records,
    filter_kev,
    load_cve_input,
    load_epss_map,
    load_kev_set,
)

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "examples")


def test_load_cve_input_id_list(tmp_path):
    p = tmp_path / "in.json"
    p.write_text(json.dumps(["CVE-2024-10001", "CVE-2024-10002"]))
    recs = load_cve_input(str(p))
    assert [r["cve_id"] for r in recs] == ["CVE-2024-10001", "CVE-2024-10002"]


def test_load_cve_input_records_and_wrapper(tmp_path):
    p = tmp_path / "in.json"
    p.write_text(json.dumps({"cves": [{"id": "CVE-2024-10001", "cvss": 9.8}]}))
    recs = load_cve_input(str(p))
    assert recs[0]["cve_id"] == "CVE-2024-10001"
    assert recs[0]["cvss"] == 9.8


def test_load_cve_input_rejects_non_list(tmp_path):
    p = tmp_path / "in.json"
    p.write_text(json.dumps({"foo": "bar"}))
    with pytest.raises(ValueError):
        load_cve_input(str(p))


def test_kev_fixture_catalog_shape():
    kev = load_kev_set(EXAMPLES)
    assert "CVE-2024-10001" in kev
    assert "CVE-2024-10003" in kev
    assert "CVE-2024-10002" not in kev


def test_epss_fixture_map():
    epss = load_epss_map(EXAMPLES)
    assert epss["CVE-2024-10001"] == 0.94


def test_enrich_merges_all_signals_offline():
    recs = [{"cve_id": "CVE-2024-10001"}]
    enriched = enrich_records(recs, fixtures_dir=EXAMPLES, live=False)
    e = enriched[0]
    assert e["cvss"] == 9.8
    assert e["epss"] == 0.94
    assert e["kev"] is True


def test_enrich_sets_kev_false_when_absent():
    recs = [{"cve_id": "CVE-2024-10002"}]
    enriched = enrich_records(recs, fixtures_dir=EXAMPLES, live=False)
    assert enriched[0]["kev"] is False


def test_enrich_preserves_existing_values():
    recs = [{"cve_id": "CVE-2024-10001", "cvss": 1.0}]
    enriched = enrich_records(recs, fixtures_dir=EXAMPLES, live=False)
    # input cvss is authoritative; not overwritten by fixture 9.8
    assert enriched[0]["cvss"] == 1.0


def test_enrich_explicit_kev_true_honored_even_if_not_in_catalog():
    recs = [{"cve_id": "CVE-2024-10005", "kev": True}]
    enriched = enrich_records(recs, fixtures_dir=EXAMPLES, live=False)
    assert enriched[0]["kev"] is True


def test_enrich_missing_fixtures_dir_is_tolerated(tmp_path):
    recs = [{"cve_id": "CVE-2024-10001"}]
    enriched = enrich_records(recs, fixtures_dir=str(tmp_path), live=False)
    # no fixtures -> no enrichment, kev defaults False
    assert enriched[0].get("cvss") is None
    assert enriched[0]["kev"] is False


def test_filter_kev():
    recs = [
        {"cve_id": "A", "kev": True},
        {"cve_id": "B", "kev": False},
        {"cve_id": "C", "kev": True},
    ]
    assert [r["cve_id"] for r in filter_kev(recs)] == ["A", "C"]
