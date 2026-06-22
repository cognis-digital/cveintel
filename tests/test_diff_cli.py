"""CLI-level tests for `cveintel diff`: table, JSON, gate, flags, errors."""

import json
import os

import pytest

from cveintel.cli import EXIT_ERROR, EXIT_GATE, EXIT_OK, main


def write(tmp_path, name, payload):
    p = tmp_path / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return str(p)


@pytest.fixture
def empty_fixtures(tmp_path):
    # An empty fixtures dir so inline record signals are authoritative and no
    # bundled-examples catalog can promote/alter our synthetic CVEs.
    d = tmp_path / "fx"
    d.mkdir()
    return str(d)


@pytest.fixture
def snapshots(tmp_path):
    before = write(
        tmp_path,
        "before.json",
        [
            {"cve_id": "CVE-2024-0001", "cvss": 7.5, "epss": 0.10, "kev": False},
            {"cve_id": "CVE-2024-0002", "cvss": 5.0, "epss": 0.05, "kev": False},
        ],
    )
    after = write(
        tmp_path,
        "after.json",
        [
            {"cve_id": "CVE-2024-0001", "cvss": 7.5, "epss": 0.90, "kev": True},
            {"cve_id": "CVE-2024-0003", "cvss": 9.8, "epss": 0.95, "kev": True},
        ],
    )
    return before, after


def test_diff_table_runs(snapshots, empty_fixtures, capsys):
    before, after = snapshots
    rc = main(["diff", before, after, "--fixtures", empty_fixtures])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "CVE-2024-0001" in out
    assert "changed" in out


def test_diff_json_structure(snapshots, empty_fixtures, capsys):
    before, after = snapshots
    rc = main(["diff", before, after, "--fixtures", empty_fixtures, "--json"])
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert set(data) == {"summary", "drift"}
    ids = {d["cve_id"] for d in data["drift"]}
    # 0001 worsened, 0002 resolved, 0003 appeared
    assert ids == {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}


def test_diff_summary_counts(snapshots, empty_fixtures, capsys):
    before, after = snapshots
    main(["diff", before, after, "--fixtures", empty_fixtures, "--json"])
    summary = json.loads(capsys.readouterr().out)["summary"]
    assert summary["kev_added"] == 2
    assert summary["resolved"] == 1
    assert summary["appeared"] == 1
    assert summary["worsened"] == 2


def test_diff_fail_on_drift_trips_gate(snapshots, empty_fixtures):
    before, after = snapshots
    rc = main(["diff", before, after, "--fixtures", empty_fixtures, "--fail-on-drift"])
    assert rc == EXIT_GATE


def test_diff_fail_on_drift_clean_when_no_worsening(tmp_path, empty_fixtures):
    snap = write(
        tmp_path, "s.json", [{"cve_id": "CVE-2024-0001", "cvss": 7.5, "epss": 0.5, "kev": True}]
    )
    rc = main(["diff", snap, snap, "--fixtures", empty_fixtures, "--fail-on-drift"])
    assert rc == EXIT_OK


def test_diff_identical_snapshots_report_no_drift(tmp_path, empty_fixtures, capsys):
    snap = write(
        tmp_path, "s.json", [{"cve_id": "CVE-2024-0001", "cvss": 7.5, "epss": 0.5, "kev": True}]
    )
    rc = main(["diff", snap, snap, "--fixtures", empty_fixtures])
    assert rc == EXIT_OK
    assert "no posture drift" in capsys.readouterr().out


def test_diff_worsened_only_filters_table(snapshots, empty_fixtures, capsys):
    before, after = snapshots
    rc = main(
        ["diff", before, after, "--fixtures", empty_fixtures, "--worsened-only", "--json"]
    )
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    ids = {d["cve_id"] for d in data["drift"]}
    # resolved CVE-2024-0002 dropped
    assert "CVE-2024-0002" not in ids
    assert ids == {"CVE-2024-0001", "CVE-2024-0003"}


def _note_lines(out):
    return [ln for ln in out.splitlines() if ln.startswith("    - ")]


def test_diff_no_reasons_suppresses_notes(snapshots, empty_fixtures, capsys):
    before, after = snapshots
    main(["diff", before, after, "--fixtures", empty_fixtures, "--no-reasons"])
    assert _note_lines(capsys.readouterr().out) == []


def test_diff_table_shows_notes_by_default(snapshots, empty_fixtures, capsys):
    before, after = snapshots
    main(["diff", before, after, "--fixtures", empty_fixtures])
    assert _note_lines(capsys.readouterr().out)


def test_diff_missing_file_errors(tmp_path, empty_fixtures):
    good = write(tmp_path, "g.json", [{"cve_id": "CVE-2024-0001"}])
    rc = main(["diff", good, str(tmp_path / "nope.json"), "--fixtures", empty_fixtures])
    assert rc == EXIT_ERROR


def test_diff_worsened_flag_marks_table_lines(snapshots, empty_fixtures, capsys):
    before, after = snapshots
    main(["diff", before, after, "--fixtures", empty_fixtures])
    out = capsys.readouterr().out
    # worsened items carry the "!" flag in the table
    assert "!" in out
