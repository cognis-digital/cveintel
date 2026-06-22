"""Enrichment: merge CVSS / KEV / EPSS signals onto CVE records.

Offline by default: signals come from local fixture JSON shipped under
``examples/`` (or any directory passed via ``--fixtures``). Live fetching is
isolated in :mod:`cveintel.live` and only invoked when ``--live`` is passed;
no network code runs in the default/offline path or in tests.
"""

from __future__ import annotations

import json
import os
from typing import Iterable, Optional

# Default fixture filenames looked up inside a fixtures directory.
KEV_FIXTURE = "kev.json"
EPSS_FIXTURE = "epss.json"
NVD_FIXTURE = "nvd.json"


def _read_json(path: str) -> object:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_cve_input(path: str) -> list[dict]:
    """Load the user-supplied CVE input file.

    Accepts either:
      * a JSON list of CVE-id strings, e.g. ``["CVE-2024-0001", ...]``
      * a JSON list of record objects, e.g. ``[{"cve_id": "...", ...}]``
      * an object with a ``"cves"`` key wrapping either of the above
    Returns a list of record dicts (each with at least ``cve_id``).
    """
    data = _read_json(path)

    if isinstance(data, dict) and "cves" in data:
        data = data["cves"]

    if not isinstance(data, list):
        raise ValueError("CVE input must be a JSON list (or {'cves': [...]})")

    records: list[dict] = []
    for item in data:
        if isinstance(item, str):
            records.append({"cve_id": item})
        elif isinstance(item, dict):
            rec = dict(item)
            cid = rec.get("cve_id") or rec.get("id") or rec.get("cve")
            if not cid:
                raise ValueError(f"record missing CVE id: {rec!r}")
            rec["cve_id"] = str(cid)
            records.append(rec)
        else:
            raise ValueError(f"unsupported CVE input element: {item!r}")
    return records


def load_kev_set(fixtures_dir: str) -> set[str]:
    """Load the set of KEV-listed CVE ids from a fixture.

    Fixture format: a JSON list of ids, or the CISA KEV catalog shape
    (``{"vulnerabilities": [{"cveID": "..."}, ...]}``).
    """
    path = os.path.join(fixtures_dir, KEV_FIXTURE)
    if not os.path.exists(path):
        return set()
    data = _read_json(path)
    if isinstance(data, dict) and "vulnerabilities" in data:
        return {
            str(v.get("cveID") or v.get("cve_id"))
            for v in data["vulnerabilities"]
            if (v.get("cveID") or v.get("cve_id"))
        }
    if isinstance(data, list):
        return {str(x) for x in data}
    raise ValueError("KEV fixture must be a list or CISA-catalog object")


def load_epss_map(fixtures_dir: str) -> dict[str, float]:
    """Load a mapping of CVE id -> EPSS probability from a fixture.

    Fixture format: an object ``{"CVE-...": 0.92, ...}`` or the EPSS API
    shape (``{"data": [{"cve": "...", "epss": "0.92"}, ...]}``).
    """
    path = os.path.join(fixtures_dir, EPSS_FIXTURE)
    if not os.path.exists(path):
        return {}
    data = _read_json(path)
    if isinstance(data, dict) and "data" in data:
        return {
            str(row["cve"]): float(row["epss"])
            for row in data["data"]
            if row.get("cve") is not None and row.get("epss") is not None
        }
    if isinstance(data, dict):
        return {str(k): float(v) for k, v in data.items()}
    raise ValueError("EPSS fixture must be an object or EPSS-API object")


def load_cvss_map(fixtures_dir: str) -> dict[str, float]:
    """Load a mapping of CVE id -> CVSS base score from the NVD fixture.

    Fixture format: an object ``{"CVE-...": 9.8, ...}`` or a list of records
    ``[{"cve_id": "...", "cvss": 9.8}, ...]``.
    """
    path = os.path.join(fixtures_dir, NVD_FIXTURE)
    if not os.path.exists(path):
        return {}
    data = _read_json(path)
    if isinstance(data, list):
        out: dict[str, float] = {}
        for row in data:
            cid = row.get("cve_id") or row.get("id") or row.get("cve")
            if cid is not None and row.get("cvss") is not None:
                out[str(cid)] = float(row["cvss"])
        return out
    if isinstance(data, dict):
        return {str(k): float(v) for k, v in data.items()}
    raise ValueError("NVD fixture must be an object or a list of records")


def enrich_records(
    records: list[dict],
    fixtures_dir: str,
    live: bool = False,
    live_timeout: float = 20.0,
    feeds: bool = False,
    offline: bool = False,
) -> list[dict]:
    """Merge CVSS / KEV / EPSS signals onto a list of CVE records.

    Existing values already on a record are preserved (the input is treated as
    authoritative); only missing fields are filled from the signal sources.

    Signal source precedence:
      * ``feeds=True``  -> the edge/air-gap feed cache (:mod:`cveintel.feeds`).
        With ``offline=True`` it serves cached cisa-kev/epss/nvd-cve only and
        never touches the network (raises if a feed was never cached).
      * ``live=True``   -> the legacy isolated :mod:`cveintel.live` fetchers.
      * otherwise       -> local fixture JSON under ``fixtures_dir``.
    """
    cve_ids = [r["cve_id"] for r in records]

    if feeds:
        # Edge/air-gap path via the bundled feed engine; offline serves cache.
        from . import feeds as feeds_mod

        kev_set, epss_map, cvss_map = feeds_mod.signals(cve_ids, offline=offline)
    elif live:
        # Network path - isolated, never exercised by the offline tests.
        from . import live as live_mod

        kev_set = live_mod.fetch_kev_set(timeout=live_timeout)
        epss_map = live_mod.fetch_epss_map(cve_ids, timeout=live_timeout)
        cvss_map = live_mod.fetch_cvss_map(cve_ids, timeout=live_timeout)
    else:
        kev_set = load_kev_set(fixtures_dir)
        epss_map = load_epss_map(fixtures_dir)
        cvss_map = load_cvss_map(fixtures_dir)

    enriched: list[dict] = []
    for rec in records:
        out = dict(rec)
        cid = out["cve_id"]

        if out.get("cvss") is None and cid in cvss_map:
            out["cvss"] = cvss_map[cid]
        if out.get("epss") is None and cid in epss_map:
            out["epss"] = epss_map[cid]
        if "kev" not in out or out.get("kev") is None:
            out["kev"] = cid in kev_set
        else:
            # Honor explicit kev=True from input, but let the catalog promote.
            out["kev"] = bool(out["kev"]) or (cid in kev_set)

        enriched.append(out)
    return enriched


def filter_kev(records: Iterable[dict]) -> list[dict]:
    """Return only records flagged as KEV-listed."""
    return [r for r in records if bool(r.get("kev"))]


def default_fixtures_dir() -> Optional[str]:
    """Best-effort path to the bundled examples/ fixtures directory."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.normpath(os.path.join(here, "..", "examples"))
    return candidate if os.path.isdir(candidate) else None
