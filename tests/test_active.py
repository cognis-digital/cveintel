"""Tests for ACTIVE, authorization-gated probing.

All tests run against localhost / a bundled fixture HTTP server / mocks ONLY.
No test contacts a real external host.
"""

from __future__ import annotations

import http.server
import threading

import pytest

from cveintel.active import (
    AUTHORIZED_USE_BANNER,
    ActiveProbe,
    ProbeResult,
    ScopeError,
    banners_to_findings,
    extract_products,
    host_in_scope,
)


# --- localhost fixture server ---------------------------------------------
class _Handler(http.server.BaseHTTPRequestHandler):
    server_header = "nginx/1.18.0"
    powered_by = "PHP/7.4.3"

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        if self.server_header:
            self.send_header("Server", self.server_header)
        if self.powered_by:
            self.send_header("X-Powered-By", self.powered_by)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):  # silence
        pass


@pytest.fixture()
def local_server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}/", port
    srv.shutdown()


# --- gating ----------------------------------------------------------------
def test_requires_authorization():
    with pytest.raises(PermissionError):
        ActiveProbe(allowlist=["localhost"], authorized=False, rate_limit=10)


def test_requires_nonempty_allowlist():
    with pytest.raises(ScopeError):
        ActiveProbe(allowlist=[], authorized=True, rate_limit=10)


def test_requires_nonblank_allowlist():
    with pytest.raises(ScopeError):
        ActiveProbe(allowlist=["", "  "], authorized=True, rate_limit=10)


def test_rate_limit_must_be_positive():
    with pytest.raises(ValueError):
        ActiveProbe(allowlist=["localhost"], authorized=True, rate_limit=0)


def test_negative_rate_limit_rejected():
    with pytest.raises(ValueError):
        ActiveProbe(allowlist=["localhost"], authorized=True, rate_limit=-5)


def test_authorized_probe_constructs():
    p = ActiveProbe(allowlist=["localhost"], authorized=True, rate_limit=10)
    assert p.authorized is True
    assert p.min_interval == pytest.approx(0.1)


def test_banner_text_present():
    assert "AUTHORIZED USE ONLY" in AUTHORIZED_USE_BANNER


# --- scope enforcement -----------------------------------------------------
def test_host_in_scope_exact():
    assert host_in_scope("example.com", ["example.com"])


def test_host_not_in_scope():
    assert not host_in_scope("evil.com", ["example.com"])


def test_host_in_scope_wildcard():
    assert host_in_scope("api.example.com", ["*.example.com"])


def test_host_in_scope_wildcard_apex():
    assert host_in_scope("example.com", ["*.example.com"])


def test_host_in_scope_empty_allowlist():
    assert not host_in_scope("example.com", [])


def test_host_in_scope_blank_host():
    assert not host_in_scope("", ["example.com"])


def test_check_scope_returns_host():
    p = ActiveProbe(allowlist=["localhost"], authorized=True, rate_limit=10)
    assert p.check_scope("http://localhost:8080/x") == "localhost"


def test_check_scope_refuses_out_of_scope():
    p = ActiveProbe(allowlist=["localhost"], authorized=True, rate_limit=10)
    with pytest.raises(ScopeError):
        p.check_scope("http://attacker.example/")


def test_probe_out_of_scope_raises():
    p = ActiveProbe(allowlist=["localhost"], authorized=True, rate_limit=10)
    with pytest.raises(ScopeError):
        p.probe("http://not-allowed.test/")


# --- extract_products ------------------------------------------------------
def test_extract_products_server_nginx():
    prods = extract_products({"Server": "nginx/1.18.0"})
    assert any(p["name"] == "nginx" and p["version"] == "1.18.0" for p in prods)


def test_extract_products_x_powered_by_php():
    prods = extract_products({"X-Powered-By": "PHP/7.4.3"})
    assert any(p["name"] == "php" and p["version"] == "7.4.3" for p in prods)


def test_extract_products_apache():
    prods = extract_products({"Server": "Apache/2.4.41 (Ubuntu)"})
    assert any(p["name"] == "httpd" for p in prods)


def test_extract_products_no_banner():
    assert extract_products({"Content-Type": "text/html"}) == []


def test_extract_products_case_insensitive_header():
    prods = extract_products({"server": "nginx/1.0.0"})
    assert any(p["name"] == "nginx" for p in prods)


def test_extract_products_no_version():
    prods = extract_products({"Server": "nginx"})
    assert prods and prods[0]["version"] is None


# --- end-to-end against localhost -----------------------------------------
def test_probe_localhost_reads_headers(local_server):
    url, _ = local_server
    p = ActiveProbe(allowlist=["127.0.0.1"], authorized=True, rate_limit=50)
    res = p.probe(url)
    assert res.status == 200
    assert any("nginx" in b for b in res.banners)
    assert any(prod["name"] == "nginx" for prod in res.products)
    assert res.error is None


def test_scan_skips_out_of_scope(local_server):
    url, _ = local_server
    p = ActiveProbe(allowlist=["127.0.0.1"], authorized=True, rate_limit=50)
    results, _ = p.scan([url, "http://offsite.example/"])
    skipped = [r for r in results if r.error and "out of scope" in r.error]
    assert len(skipped) == 1


def test_scan_hard_fail_out_of_scope(local_server):
    url, _ = local_server
    p = ActiveProbe(allowlist=["127.0.0.1"], authorized=True, rate_limit=50)
    with pytest.raises(ScopeError):
        p.scan(["http://offsite.example/"], skip_out_of_scope=False)


def test_probe_connection_error_recorded():
    # in scope but nothing listening on this port -> error captured, not raised
    p = ActiveProbe(allowlist=["127.0.0.1"], authorized=True, rate_limit=50, timeout=1)
    res = p.probe("http://127.0.0.1:1/")
    assert res.error is not None
    assert res.status is None


# --- rate limiting (injected clock/sleep, no real waiting) ----------------
def test_rate_limit_throttles():
    sleeps = []
    t = {"now": 0.0}

    def clock():
        return t["now"]

    def sleep(s):
        sleeps.append(s)
        t["now"] += s

    def fake_opener(req, timeout):
        class R:
            status = 200
            headers = {"Server": "nginx/1.0.0"}

            def close(self):
                pass

        return R()

    p = ActiveProbe(
        allowlist=["127.0.0.1"],
        authorized=True,
        rate_limit=2.0,  # 0.5s min interval
        opener=fake_opener,
        clock=clock,
        sleep=sleep,
    )
    p.probe("http://127.0.0.1/a")
    p.probe("http://127.0.0.1/b")  # immediate -> should throttle ~0.5s
    assert sleeps and sleeps[0] == pytest.approx(0.5, abs=1e-6)


def test_no_throttle_on_first_request():
    sleeps = []

    def fake_opener(req, timeout):
        class R:
            status = 200
            headers = {}

            def close(self):
                pass

        return R()

    p = ActiveProbe(
        allowlist=["127.0.0.1"],
        authorized=True,
        rate_limit=1.0,
        opener=fake_opener,
        clock=lambda: 0.0,
        sleep=lambda s: sleeps.append(s),
    )
    p.probe("http://127.0.0.1/a")
    assert sleeps == []


# --- banners_to_findings ---------------------------------------------------
def test_banners_to_findings_no_products():
    assert banners_to_findings([]) == []


def test_banners_to_findings_unknown_product():
    assert banners_to_findings([{"name": "totally-unknown-zzz", "version": "1"}]) == []


def test_probe_result_to_dict_roundtrip():
    r = ProbeResult(target="http://x/", host="x", status=200)
    d = r.to_dict()
    assert d["target"] == "http://x/" and d["status"] == 200
