"""Tests for the CLI: subcommands, JSON output, --fail-on exit codes."""

import json
import os

import pytest

from cveintel.cli import EXIT_GATE, EXIT_OK, main

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "examples")
CVES = os.path.join(EXAMPLES, "cves.json")


def run(argv):
    return main(argv)


def test_rank_table_offline(capsys):
    rc = run(["rank", CVES, "--fixtures", EXAMPLES])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    # most severe (KEV + high CVSS + high EPSS) appears first
    lines = [l for l in out.splitlines() if l.startswith("CVE-2024-")]
    assert lines[0].startswith("CVE-2024-10001")
    assert "CRITICAL" in lines[0]


def test_rank_json_offline(capsys):
    rc = run(["rank", CVES, "--fixtures", EXAMPLES, "--json"])
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data[0]["cve_id"] == "CVE-2024-10001"
    assert data[0]["tier"] == "CRITICAL"
    # descending score
    scores = [d["score"] for d in data]
    assert scores == sorted(scores, reverse=True)
    # reasons present and explain KEV
    assert any("KEV" in r or "kev" in r.lower() for r in data[0]["reasons"])


def test_enrich_json_offline(capsys):
    rc = run(["enrich", CVES, "--fixtures", EXAMPLES, "--json"])
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    first = next(d for d in data if d["cve_id"] == "CVE-2024-10001")
    assert first["cvss"] == 9.8
    assert first["epss"] == 0.94
    assert first["kev"] is True


def test_kev_filter_json_offline(capsys):
    rc = run(["kev", CVES, "--fixtures", EXAMPLES, "--json"])
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    ids = {d["cve_id"] for d in data}
    assert ids == {"CVE-2024-10001", "CVE-2024-10003"}


def test_fail_on_critical_triggers_gate(capsys):
    # examples contain a CRITICAL CVE -> gate should fire
    rc = run(["rank", CVES, "--fixtures", EXAMPLES, "--fail-on", "critical"])
    assert rc == EXIT_GATE


def test_fail_on_high_triggers_gate(capsys):
    rc = run(["rank", CVES, "--fixtures", EXAMPLES, "--fail-on", "high"])
    assert rc == EXIT_GATE


def test_fail_on_does_not_trigger_for_low_only(tmp_path, capsys):
    # only a single LOW-tier CVE -> gate must NOT fire
    low_in = tmp_path / "low.json"
    low_in.write_text(json.dumps(["CVE-2024-10006"]))
    rc = run(["rank", str(low_in), "--fixtures", EXAMPLES, "--fail-on", "critical"])
    assert rc == EXIT_OK
    rc = run(["rank", str(low_in), "--fixtures", EXAMPLES, "--fail-on", "high"])
    assert rc == EXIT_OK


def test_enrich_fail_on_gate(capsys):
    rc = run(["enrich", CVES, "--fixtures", EXAMPLES, "--fail-on", "critical"])
    assert rc == EXIT_GATE


def test_missing_input_file_returns_error():
    rc = run(["rank", "does-not-exist.json", "--fixtures", EXAMPLES])
    assert rc == 1


def test_no_subcommand_errors():
    with pytest.raises(SystemExit):
        run([])
