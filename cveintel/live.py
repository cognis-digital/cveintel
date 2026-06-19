"""Live data fetchers (NVD / CISA KEV / EPSS).

Isolated network layer. Only imported and called when the CLI is run with
``--live``. The offline path and the test suite never touch this module, so it
keeps cveintel hermetic by default. Standard library only (urllib).
"""

from __future__ import annotations

import json
import urllib.request
from typing import Iterable

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_USER_AGENT = "cveintel/0.1 (Cognis Digital; defensive triage)"


def _get_json(url: str, timeout: float) -> object:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))


def fetch_kev_set(timeout: float = 20.0) -> set[str]:
    """Fetch the live CISA KEV catalog and return the set of CVE ids."""
    data = _get_json(KEV_URL, timeout)
    vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    return {str(v["cveID"]) for v in vulns if v.get("cveID")}


def fetch_epss_map(cve_ids: Iterable[str], timeout: float = 20.0) -> dict[str, float]:
    """Fetch EPSS probabilities for the given CVE ids from the FIRST API."""
    ids = [c for c in cve_ids if c]
    out: dict[str, float] = {}
    # The EPSS API accepts a comma-separated cve list; chunk to keep URLs sane.
    for i in range(0, len(ids), 100):
        chunk = ids[i : i + 100]
        url = f"{EPSS_URL}?cve={','.join(chunk)}"
        data = _get_json(url, timeout)
        for row in data.get("data", []) if isinstance(data, dict) else []:
            if row.get("cve") and row.get("epss") is not None:
                out[str(row["cve"])] = float(row["epss"])
    return out


def fetch_cvss_map(cve_ids: Iterable[str], timeout: float = 20.0) -> dict[str, float]:
    """Fetch CVSS base scores for the given CVE ids from the NVD 2.0 API.

    Prefers CVSS v3.1, then v3.0, then v2 base scores when present.
    """
    out: dict[str, float] = {}
    for cid in cve_ids:
        if not cid:
            continue
        url = f"{NVD_URL}?cveId={cid}"
        try:
            data = _get_json(url, timeout)
        except Exception:
            continue
        for item in data.get("vulnerabilities", []) if isinstance(data, dict) else []:
            metrics = item.get("cve", {}).get("metrics", {})
            score = _best_cvss(metrics)
            if score is not None:
                out[cid] = score
    return out


def _best_cvss(metrics: dict) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            base = data.get("baseScore")
            if base is not None:
                return float(base)
    return None
