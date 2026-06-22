"""CLI-level tests for the sbom (passive) and active (gated) subcommands."""

from __future__ import annotations

import json

import pytest

from cveintel.cli import main


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(json.dumps(content), encoding="utf-8")
    return str(p)


# --- sbom ------------------------------------------------------------------
def test_cli_sbom_table(tmp_path, capsys):
    path = _write(tmp_path, "s.json", ["tar"])
    rc = main(["sbom", path, "--no-reasons"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "passive scan" in out
    assert "CVE" in out


def test_cli_sbom_json(tmp_path, capsys):
    path = _write(tmp_path, "s.json", ["tar"])
    rc = main(["sbom", path, "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert isinstance(data, list)
    assert all("cve_id" in d for d in data)


def test_cli_sbom_sarif(tmp_path, capsys):
    path = _write(tmp_path, "s.json", ["tar"])
    rc = main(["sbom", path, "--sarif"])
    out = capsys.readouterr().out
    assert rc == 0
    sarif = json.loads(out)
    assert sarif["version"] == "2.1.0"


def test_cli_sbom_empty(tmp_path, capsys):
    path = _write(tmp_path, "s.json", [])
    rc = main(["sbom", path])
    assert rc == 0


def test_cli_sbom_unknown_pkg_zero(tmp_path, capsys):
    path = _write(tmp_path, "s.json", ["nonexistent-zzz-pkg"])
    rc = main(["sbom", path, "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data == []
    assert rc == 0


# --- active gating via CLI -------------------------------------------------
def test_cli_active_refuses_without_authorized(capsys):
    rc = main(["active", "http://localhost/", "--target-allowlist", "localhost"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "REFUSED" in err
    assert "authoriz" in err.lower()


def test_cli_active_refuses_without_allowlist(capsys):
    rc = main(["active", "http://localhost/", "--authorized"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "REFUSED" in err


def test_cli_active_refuses_bad_rate_limit(capsys):
    rc = main(
        [
            "active",
            "http://localhost/",
            "--authorized",
            "--target-allowlist",
            "localhost",
            "--rate-limit",
            "0",
        ]
    )
    assert rc == 1
    assert "REFUSED" in capsys.readouterr().err


def test_cli_active_prints_banner_to_stderr(capsys):
    main(["active", "http://localhost/", "--target-allowlist", "localhost"])
    err = capsys.readouterr().err
    assert "AUTHORIZED USE ONLY" in err


def test_cli_active_out_of_scope_skipped(capsys):
    # authorized + scoped to localhost, but target is offsite -> skipped, no probe
    rc = main(
        [
            "active",
            "http://offsite.example/",
            "--authorized",
            "--target-allowlist",
            "localhost",
            "--rate-limit",
            "50",
            "--json",
        ]
    )
    out = capsys.readouterr().out
    data = json.loads(out)
    assert rc == 0
    assert any("out of scope" in (p.get("error") or "") for p in data["probes"])


def test_cli_active_localhost(capsys):
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Server", "nginx/1.18.0")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        rc = main(
            [
                "active",
                f"http://127.0.0.1:{port}/",
                "--authorized",
                "--target-allowlist",
                "127.0.0.1",
                "--rate-limit",
                "50",
                "--json",
            ]
        )
        data = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert data["probes"][0]["status"] == 200
        assert any("nginx" in b for b in data["probes"][0]["banners"])
    finally:
        srv.shutdown()


# --- vulndb flag on rank ---------------------------------------------------
def test_cli_rank_vulndb_flag(tmp_path, capsys):
    # CVE not in fixtures; --vulndb should still run without error
    path = _write(tmp_path, "c.json", ["CVE-1900-99999"])
    rc = main(["rank", path, "--vulndb", "--json", "--fixtures", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    json.loads(out)
