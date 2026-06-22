"""Tests for the passive vuln-DB matching / SBOM scanning layer (offline)."""

from __future__ import annotations

import json
import os

import pytest

from cveintel import vulnmatch
from cveintel.vulnmatch import (
    cvss_vector_base_score,
    enrich_from_vulndb,
    load_sbom,
    scan_sbom,
    severity_to_cvss,
)


# --- severity_to_cvss -----------------------------------------------------
def test_severity_bare_numeric():
    assert severity_to_cvss("9.8") == 9.8


def test_severity_int():
    assert severity_to_cvss(7) == 7.0


def test_severity_none():
    assert severity_to_cvss(None) is None


def test_severity_empty_string():
    assert severity_to_cvss("") is None


def test_severity_word_high():
    assert severity_to_cvss("HIGH") == 8.0


def test_severity_word_critical():
    assert severity_to_cvss("critical") == 9.5


def test_severity_word_low():
    assert severity_to_cvss("Low") == 3.0


def test_severity_moderate_alias():
    assert severity_to_cvss("moderate") == severity_to_cvss("medium")


def test_severity_out_of_range_rejected():
    assert severity_to_cvss("99") is None
    assert severity_to_cvss("-1") is None


def test_severity_list_of_osv_dicts():
    sev = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}]
    assert severity_to_cvss(sev) == 10.0


def test_severity_dict():
    assert severity_to_cvss({"score": "7.5"}) == 7.5


def test_severity_unparseable_text():
    assert severity_to_cvss("not-a-score") is None


# --- CVSS v3.1 vector math (known reference values) -----------------------
def test_cvss_log4shell_is_10():
    # CVE-2021-44228 published vector.
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert cvss_vector_base_score(v) == 10.0


def test_cvss_high_integrity_only():
    # AV:N/AC:L/PR:N/UI:N/S:U with only Integrity High -> 7.5 (matches NVD)
    v = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
    assert cvss_vector_base_score(v) == 7.5


def test_cvss_low_vector():
    v = "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L"
    score = cvss_vector_base_score(v)
    assert score is not None and 2.0 <= score <= 4.0


def test_cvss_none_impact_is_zero():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    assert cvss_vector_base_score(v) == 0.0


def test_cvss_missing_metrics_returns_none():
    assert cvss_vector_base_score("CVSS:3.1/AV:N") is None


def test_cvss_v4_approx_in_range():
    v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
    score = cvss_vector_base_score(v)
    assert score is not None and 0.0 <= score <= 10.0


def test_cvss_v4_no_impact_none():
    assert cvss_vector_base_score("CVSS:4.0/AV:N/AC:L") is None


def test_cvss_scope_changed_higher_than_unchanged():
    base = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/{}/C:H/I:H/A:H"
    changed = cvss_vector_base_score(base.format("S:C"))
    unchanged = cvss_vector_base_score(base.format("S:U"))
    assert changed >= unchanged


# --- load_sbom (multiple shapes) ------------------------------------------
def _write(tmp_path, name, content):
    p = tmp_path / name
    if isinstance(content, (dict, list)):
        p.write_text(json.dumps(content), encoding="utf-8")
    else:
        p.write_text(content, encoding="utf-8")
    return str(p)


def test_sbom_json_list_of_names(tmp_path):
    path = _write(tmp_path, "s.json", ["tar", "deno"])
    pkgs = load_sbom(path)
    assert [p["name"] for p in pkgs] == ["tar", "deno"]


def test_sbom_json_list_of_objects(tmp_path):
    path = _write(tmp_path, "s.json", [{"name": "tar", "ecosystem": "npm"}])
    pkgs = load_sbom(path)
    assert pkgs[0]["name"] == "tar" and pkgs[0]["ecosystem"] == "npm"


def test_sbom_cyclonedx(tmp_path):
    doc = {"components": [{"name": "lodash", "type": "library"}]}
    path = _write(tmp_path, "cdx.json", doc)
    pkgs = load_sbom(path)
    assert pkgs[0]["name"] == "lodash"


def test_sbom_cyclonedx_purl(tmp_path):
    doc = {"components": [{"purl": "pkg:npm/left-pad@1.0.0"}]}
    path = _write(tmp_path, "cdx.json", doc)
    pkgs = load_sbom(path)
    assert pkgs[0]["name"] == "left-pad"
    assert pkgs[0]["ecosystem"] == "npm"


def test_sbom_packages_key(tmp_path):
    doc = {"packages": ["foo", {"name": "bar"}]}
    path = _write(tmp_path, "spdx.json", doc)
    pkgs = load_sbom(path)
    assert {p["name"] for p in pkgs} == {"foo", "bar"}


def test_sbom_newline_text(tmp_path):
    path = _write(tmp_path, "reqs.txt", "tar\ndeno\n# comment\n\nwasmtime\n")
    pkgs = load_sbom(path)
    names = [p["name"] for p in pkgs]
    assert names == ["tar", "deno", "wasmtime"]


def test_sbom_empty_file(tmp_path):
    path = _write(tmp_path, "empty.txt", "")
    assert load_sbom(path) == []


def test_sbom_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_sbom(str(tmp_path / "nope.json"))


def test_sbom_unsupported_shape(tmp_path):
    path = _write(tmp_path, "bad.json", {"unexpected": 1})
    with pytest.raises(ValueError):
        load_sbom(path)


# --- scan_sbom against bundled corpus -------------------------------------
def test_scan_sbom_finds_cves_for_known_package(shared_db):
    findings = scan_sbom([{"name": "tar"}], db=shared_db)
    assert findings, "expected corpus hits for 'tar'"
    assert all("cve_id" in f for f in findings)


def test_scan_sbom_unknown_package_empty(shared_db):
    findings = scan_sbom([{"name": "this-package-does-not-exist-zzz"}], db=shared_db)
    assert findings == []


def test_scan_sbom_dedupes_cve_ids(shared_db):
    findings = scan_sbom([{"name": "tar"}, {"name": "tar"}], db=shared_db)
    ids = [f["cve_id"] for f in findings]
    assert len(ids) == len(set(ids))


def test_scan_sbom_blank_name_skipped(shared_db):
    assert scan_sbom([{"name": ""}, {"name": "   "}], db=shared_db) == []


def test_scan_sbom_records_have_package_source(shared_db):
    findings = scan_sbom([{"name": "tar"}], db=shared_db)
    assert all(f.get("package") == "tar" for f in findings)


def test_scan_sbom_findings_rankable(shared_db):
    from cveintel.scoring import rank_records

    findings = scan_sbom([{"name": "tar"}], db=shared_db)
    scored = rank_records(findings)
    assert scored
    # at least one finding should resolve a numeric CVSS from a vector
    assert any(s.cvss is not None for s in scored)


# --- enrich_from_vulndb ---------------------------------------------------
def test_enrich_fills_match_flag_known(shared_db):
    sample = None
    for r in shared_db:
        for a in r.get("aliases") or []:
            if str(a).startswith("CVE-"):
                sample = str(a)
                break
        if sample:
            break
    assert sample
    out = enrich_from_vulndb([{"cve_id": sample}], db=shared_db)
    assert out[0]["vulndb_match"] is True


def test_enrich_unknown_cve_match_false(shared_db):
    out = enrich_from_vulndb([{"cve_id": "CVE-1900-99999"}], db=shared_db)
    assert out[0]["vulndb_match"] is False


def test_enrich_preserves_existing_cvss(shared_db):
    out = enrich_from_vulndb([{"cve_id": "CVE-1900-99999", "cvss": 4.2}], db=shared_db)
    assert out[0]["cvss"] == 4.2


def test_enrich_is_nondestructive_on_other_fields(shared_db):
    rec = {"cve_id": "CVE-1900-99999", "note": "keep me"}
    out = enrich_from_vulndb([rec], db=shared_db)
    assert out[0]["note"] == "keep me"
    # original untouched
    assert "vulndb_match" not in rec


def test_cve_to_cvss_map_only_numeric(shared_db):
    from cveintel.vulnmatch import cve_to_cvss_map

    m = cve_to_cvss_map(["CVE-1900-99999"], db=shared_db)
    assert "CVE-1900-99999" not in m


def test_enrich_known_cve_summary_filled(shared_db):
    # find a CVE that has a summary in the corpus
    sample = None
    for r in shared_db:
        if r.get("summary"):
            for a in r.get("aliases") or []:
                if str(a).startswith("CVE-"):
                    sample = str(a)
                    break
        if sample:
            break
    assert sample
    out = enrich_from_vulndb([{"cve_id": sample}], db=shared_db)
    assert out[0].get("vulndb_summary")
