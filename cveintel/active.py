"""Active, AUTHORIZATION-GATED probing for cveintel.

================================  WARNING  ================================
AUTHORIZED USE ONLY. Active probing contacts a remote host over the network.
Only run it against systems you OWN or have EXPLICIT WRITTEN PERMISSION to
test. Unauthorized scanning may be illegal. This module deliberately performs
only the most benign interaction possible:

  * a single HTTP(S) HEAD/GET to read RESPONSE HEADERS (e.g. ``Server:``,
    ``X-Powered-By:``), and
  * a passive mapping of any disclosed product/version banners to known CVEs
    in the bundled offline corpus.

It sends NO exploit payloads, performs NO authentication attacks, NO fuzzing,
NO write/modify requests, and NO port sweeps. It is a read-only banner check.
==========================================================================

Gating (all four are enforced before any socket is opened):

  1. ``authorized=True``       — the caller affirms written authorization
                                 (CLI: the explicit ``--authorized`` flag).
  2. a non-empty ``allowlist`` — every target host must match an entry; any
                                 target not in scope is REFUSED, never probed.
  3. ``rate_limit`` (req/sec)  — a minimum inter-request delay is enforced.
  4. default OFF               — there is no implicit/active default path; the
                                 caller must construct an :class:`ActiveProbe`
                                 explicitly with these parameters.

Tests exercise this module against ``localhost`` / a bundled fixture HTTP
server / mocks ONLY — never a real external host.
"""

from __future__ import annotations

import re
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional

from .vulndb_local import VulnDB

AUTHORIZED_USE_BANNER = (
    "=" * 70 + "\n"
    "  cveintel ACTIVE MODE - AUTHORIZED USE ONLY\n"
    "  Read-only banner/header check. Only probe hosts you own or are\n"
    "  EXPLICITLY authorized in writing to test. No exploits are sent.\n"
    + "=" * 70
)

_USER_AGENT = "cveintel/0.2 (Cognis Digital; authorized defensive banner check)"

# Map a few common server banners to a product token the vuln DB can match.
# Conservative: only well-known, unambiguous server software.
_BANNER_PRODUCTS = (
    ("nginx", "nginx"),
    ("apache", "httpd"),
    ("openssl", "openssl"),
    ("openssh", "openssh"),
    ("php", "php"),
    ("iis", "iis"),
    ("jetty", "jetty"),
    ("tomcat", "tomcat"),
    ("node", "node"),
    ("express", "express"),
)

_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


class ScopeError(PermissionError):
    """Raised when an active probe is attempted outside its authorized scope."""


@dataclass
class ProbeResult:
    target: str
    host: str
    status: Optional[int] = None
    headers: dict = field(default_factory=dict)
    banners: list[str] = field(default_factory=list)
    products: list[dict] = field(default_factory=list)  # {name, version, source}
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "host": self.host,
            "status": self.status,
            "headers": self.headers,
            "banners": self.banners,
            "products": self.products,
            "error": self.error,
        }


def host_in_scope(host: str, allowlist: list[str]) -> bool:
    """True if ``host`` matches an allowlist entry.

    Matching is exact host, or a ``*.example.com`` wildcard suffix, or a bare
    domain that ``host`` is a subdomain of. Empty allowlist => nothing in scope.
    """
    if not host:
        return False
    h = host.lower().strip()
    for entry in allowlist:
        e = entry.lower().strip()
        if not e:
            continue
        if e.startswith("*."):
            suffix = e[1:]  # ".example.com"
            if h.endswith(suffix) or h == e[2:]:
                return True
        elif h == e:
            return True
    return False


def extract_products(headers: dict) -> list[dict]:
    """Pull product+version tokens from disclosing response headers."""
    out: list[dict] = []
    for hk in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        val = None
        for k, v in headers.items():
            if k.lower() == hk.lower():
                val = v
                break
        if not val:
            continue
        low = val.lower()
        for needle, product in _BANNER_PRODUCTS:
            if needle in low:
                m = _VERSION_RE.search(val)
                out.append(
                    {
                        "name": product,
                        "version": m.group(1) if m else None,
                        "source": f"{hk}: {val}",
                    }
                )
    return out


def banners_to_findings(products: list[dict], db: Optional[VulnDB] = None) -> list[dict]:
    """Map detected product banners to CVE records from the bundled corpus.

    Passive lookup against the offline DB; produces records compatible with
    :func:`cveintel.scoring.rank_records`. No network.
    """
    from .vulnmatch import severity_to_cvss

    db = db or VulnDB()
    by_cve: dict[str, dict] = {}
    for prod in products:
        name = prod.get("name")
        if not name:
            continue
        for r in db.by_package(name):
            cve_id = None
            for alias in r.get("aliases") or []:
                if str(alias).upper().startswith("CVE-"):
                    cve_id = str(alias).upper()
                    break
            cve_id = cve_id or r.get("id")
            if not cve_id:
                continue
            cvss = severity_to_cvss(r.get("severity"))
            rec = {
                "cve_id": cve_id,
                "cvss": cvss,
                "description": r.get("summary", ""),
                "product": name,
                "detected_version": prod.get("version"),
                "source": "active-banner",
            }
            prev = by_cve.get(cve_id)
            if prev is None or (cvss or -1) > (prev.get("cvss") or -1):
                by_cve[cve_id] = rec
    return list(by_cve.values())


class ActiveProbe:
    """A scope-enforced, rate-limited, read-only HTTP banner probe.

    Construct with explicit authorization + scope; there is no default-on
    convenience path. ``opener`` is injectable so tests run against a fixture
    server / mock without touching the network.
    """

    def __init__(
        self,
        allowlist: list[str],
        authorized: bool = False,
        rate_limit: float = 1.0,
        timeout: float = 10.0,
        db: Optional[VulnDB] = None,
        opener: Optional[Callable[[urllib.request.Request, float], object]] = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not authorized:
            raise PermissionError(
                "active probing requires explicit authorization "
                "(--authorized); refusing to run"
            )
        if not allowlist or not any(a.strip() for a in allowlist):
            raise ScopeError(
                "active probing requires a non-empty --target-allowlist; "
                "refusing to run with empty scope"
            )
        if rate_limit <= 0:
            raise ValueError("rate_limit must be > 0 requests/second")

        self.allowlist = [a for a in allowlist if a.strip()]
        self.authorized = True
        self.rate_limit = float(rate_limit)
        self.min_interval = 1.0 / float(rate_limit)
        self.timeout = float(timeout)
        self.db = db or VulnDB()
        self._opener = opener or self._default_opener
        self._clock = clock
        self._sleep = sleep
        self._last_request_at: Optional[float] = None

    @staticmethod
    def _default_opener(req: urllib.request.Request, timeout: float):
        return urllib.request.urlopen(req, timeout=timeout)  # noqa: S310

    def _throttle(self) -> None:
        if self._last_request_at is None:
            return
        elapsed = self._clock() - self._last_request_at
        wait = self.min_interval - elapsed
        if wait > 0:
            self._sleep(wait)

    def check_scope(self, target: str) -> str:
        """Validate ``target`` is in scope; return the host. Raise otherwise."""
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or ""
        if not host_in_scope(host, self.allowlist):
            raise ScopeError(
                f"target {target!r} (host {host!r}) is NOT in the authorized "
                f"allowlist {self.allowlist!r}; refusing to probe"
            )
        return host

    def probe(self, target: str) -> ProbeResult:
        """Read-only header probe of a single in-scope target URL."""
        host = self.check_scope(target)  # raises ScopeError if out of scope
        self._throttle()

        req = urllib.request.Request(
            target, method="GET", headers={"User-Agent": _USER_AGENT}
        )
        result = ProbeResult(target=target, host=host)
        try:
            resp = self._opener(req, self.timeout)
            self._last_request_at = self._clock()
            result.status = getattr(resp, "status", None) or (
                resp.getcode() if hasattr(resp, "getcode") else None
            )
            hdrs = {}
            raw_headers = getattr(resp, "headers", {}) or {}
            try:
                items = raw_headers.items()
            except AttributeError:
                items = []
            for k, v in items:
                hdrs[str(k)] = str(v)
            result.headers = hdrs
            for hk in ("Server", "X-Powered-By"):
                for k, v in hdrs.items():
                    if k.lower() == hk.lower() and v:
                        result.banners.append(f"{k}: {v}")
            result.products = extract_products(hdrs)
            if hasattr(resp, "close"):
                resp.close()
        except ScopeError:
            raise
        except Exception as exc:  # network error, refused, etc.
            self._last_request_at = self._clock()
            result.error = f"{type(exc).__name__}: {exc}"
        return result

    def scan(self, targets: list[str], skip_out_of_scope: bool = True):
        """Probe several targets, enforcing scope on each.

        Out-of-scope targets are SKIPPED (recorded with an error) rather than
        probed when ``skip_out_of_scope`` is True; set it False to hard-fail.
        Returns ``(results, findings)`` where findings are ranked-ready CVE
        records derived from detected banners.
        """
        results: list[ProbeResult] = []
        all_products: list[dict] = []
        for tgt in targets:
            try:
                res = self.probe(tgt)
            except ScopeError as exc:
                if not skip_out_of_scope:
                    raise
                parsed = urllib.parse.urlparse(tgt)
                res = ProbeResult(
                    target=tgt,
                    host=parsed.hostname or "",
                    error=f"SKIPPED (out of scope): {exc}",
                )
            results.append(res)
            all_products.extend(res.products)
        findings = banners_to_findings(all_products, db=self.db)
        return results, findings
