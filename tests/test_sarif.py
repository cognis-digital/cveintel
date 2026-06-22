"""Tests for the SARIF 2.1.0 export feature."""

import json
import os

from cveintel.cli import EXIT_OK, main
from cveintel.sarif import to_sarif
from cveintel.scoring import rank_records

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "examples")
CVES = os.path.join(EXAMPLES, "cves.json")


def _sample_scored():
    records = [
        {"cve_id": "CVE-2024-10001", "cvss": 9.8, "epss": 0.94, "kev": True,
         "description": "sample critical"},
        {"cve_id": "CVE-2024-10003", "cvss": 7.5, "epss": 0.42, "kev": False},
        {"cve_id": "CVE-2024-10006", "cvss": 4.3, "epss": 0.01, "kev": False},
    ]
    return rank_records(records)


def test_sarif_top_level_shape():
    log = to_sarif(_sample_scored())
    assert log["version"] == "2.1.0"
    assert "$schema" in log
    assert isinstance(log["runs"], list) and len(log["runs"]) == 1
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "cveintel"
    assert driver["version"]


def test_sarif_one_result_and_rule_per_cve():
    scored = _sample_scored()
    log = to_sarif(scored)
    run = log["runs"][0]
    assert len(run["results"]) == len(scored)
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    result_ids = {r["ruleId"] for r in run["results"]}
    assert rule_ids == result_ids
    assert result_ids == {s.cve_id for s in scored}


def test_sarif_level_mapping():
    log = to_sarif(_sample_scored())
    by_id = {r["ruleId"]: r for r in log["runs"][0]["results"]}
    # KEV + high CVSS/EPSS -> CRITICAL -> error
    assert by_id["CVE-2024-10001"]["level"] == "error"
    assert by_id["CVE-2024-10001"]["properties"]["tier"] == "CRITICAL"
    # quiet medium -> MED -> warning
    assert by_id["CVE-2024-10003"]["level"] == "warning"
    assert by_id["CVE-2024-10003"]["properties"]["tier"] == "MED"
    # low -> note
    assert by_id["CVE-2024-10006"]["level"] == "note"


def test_sarif_carries_signals_and_rank():
    log = to_sarif(_sample_scored())
    crit = next(
        r for r in log["runs"][0]["results"] if r["ruleId"] == "CVE-2024-10001"
    )
    props = crit["properties"]
    assert props["cvss"] == 9.8
    assert props["epss"] == 0.94
    assert props["kev"] is True
    assert crit["rank"] == props["score"]
    assert 0.0 <= crit["rank"] <= 100.0
    # reasons end up in the message
    assert "KEV" in crit["message"]["text"] or "kev" in crit["message"]["text"].lower()


def test_sarif_helpuri_points_at_nvd():
    log = to_sarif(_sample_scored())
    rule = log["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["helpUri"].endswith(rule["id"])
    assert "nvd.nist.gov" in rule["helpUri"]


def test_cli_rank_sarif_offline(capsys):
    rc = main(["rank", CVES, "--fixtures", EXAMPLES, "--sarif"])
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"]
    # the known-critical example CVE is present and is an error-level result
    crit = next(
        r for r in data["runs"][0]["results"] if r["ruleId"] == "CVE-2024-10001"
    )
    assert crit["level"] == "error"
