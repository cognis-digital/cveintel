"""Edge / air-gap data-feed layer for cveintel.

Thin wrapper over the bundled :mod:`cveintel.datafeeds` ingestion engine and
the :mod:`cveintel.data_feeds_2026` catalog (``data_feeds_2026.json``). It
restricts the full Cognis feed catalog to the three authoritative, keyless,
public sources this tool actually consumes:

    * ``cisa-kev``  - CISA Known Exploited Vulnerabilities catalog
    * ``epss``      - FIRST EPSS exploit-probability scores
    * ``nvd-cve``   - NIST NVD CVE API 2.0 (CVSS base severity)

Why a feed layer (vs. the legacy :mod:`cveintel.live` fetchers): the feed
engine caches every fetch to disk and can re-serve it **offline**, so cveintel
keeps enriching on disconnected / air-gapped gear. ``snapshot_export`` tars the
cache for sneakernet transfer into an enclave; ``snapshot_import`` rehydrates it.

This module is import-safe with no network access. Network only happens when
``update()`` / ``get(offline=False)`` are explicitly called.

Defensive / authorized-use intelligence only.
"""

from __future__ import annotations

from typing import Iterable, Optional

from . import datafeeds

# The feed ids cveintel is wired to consume, in display order.
RELEVANT_FEED_IDS = ["cisa-kev", "epss", "nvd-cve"]


def relevant_catalog() -> dict:
    """Return the bundled catalog filtered to cveintel's relevant feeds."""
    full = datafeeds.load_catalog()
    feeds = [f for f in full.get("feeds", []) if f["id"] in RELEVANT_FEED_IDS]
    # Preserve RELEVANT_FEED_IDS ordering.
    feeds.sort(key=lambda f: RELEVANT_FEED_IDS.index(f["id"]))
    return {"_meta": full.get("_meta", {}), "feeds": feeds}


def list_feeds() -> list[dict]:
    """List only the feeds cveintel consumes (with cache freshness)."""
    return relevant_catalog()["feeds"]


def _require_relevant(feed_id: str) -> None:
    if feed_id not in RELEVANT_FEED_IDS:
        raise KeyError(
            f"{feed_id!r} is not a cveintel feed; choose one of {RELEVANT_FEED_IDS}"
        )


def update(feed_id: str, *, query: Optional[dict] = None):
    """Fetch + cache one relevant feed (network). Returns the cache path."""
    _require_relevant(feed_id)
    return datafeeds.update(feed_id, catalog=relevant_catalog(), query=query)


def get(feed_id: str, *, offline: bool = False, query: Optional[dict] = None):
    """Return parsed feed content, optionally served from cache (``offline``)."""
    _require_relevant(feed_id)
    return datafeeds.get(
        feed_id, offline=offline, catalog=relevant_catalog(), query=query
    )


# --------------------------------------------------------------------------- #
# Signal extraction: turn raw feed payloads into the maps enrich.py expects.
# These accept already-parsed feed content so they are pure + testable offline.
# --------------------------------------------------------------------------- #
def kev_set_from_feed(payload: object) -> set[str]:
    """CISA KEV catalog payload -> set of KEV-listed CVE ids."""
    if isinstance(payload, dict):
        vulns = payload.get("vulnerabilities", [])
        return {str(v["cveID"]) for v in vulns if v.get("cveID")}
    if isinstance(payload, list):
        return {str(x) for x in payload}
    return set()


def epss_map_from_feed(payload: object) -> dict[str, float]:
    """FIRST EPSS API payload -> {cve_id: probability}."""
    out: dict[str, float] = {}
    if isinstance(payload, dict) and "data" in payload:
        for row in payload["data"]:
            if row.get("cve") and row.get("epss") is not None:
                out[str(row["cve"])] = float(row["epss"])
    elif isinstance(payload, dict):
        out = {str(k): float(v) for k, v in payload.items()}
    return out


def _best_cvss(metrics: dict) -> Optional[float]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            base = entries[0].get("cvssData", {}).get("baseScore")
            if base is not None:
                return float(base)
    return None


def cvss_map_from_feed(payload: object) -> dict[str, float]:
    """NVD CVE API 2.0 payload -> {cve_id: CVSS base score}."""
    out: dict[str, float] = {}
    if isinstance(payload, dict):
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id")
            score = _best_cvss(cve.get("metrics", {}))
            if cid and score is not None:
                out[str(cid)] = score
    return out


def signals(
    cve_ids: Iterable[str],
    *,
    offline: bool = False,
) -> tuple[set[str], dict[str, float], dict[str, float]]:
    """Pull (kev_set, epss_map, cvss_map) from the feed cache / network.

    With ``offline=True`` every signal is served from the local disk cache and
    no network access occurs (raises if a feed has never been cached). EPSS and
    NVD are queried for the specific ``cve_ids`` when fetched live.
    """
    ids = [c for c in cve_ids if c]

    kev_set = kev_set_from_feed(get("cisa-kev", offline=offline))
    epss_map = epss_map_from_feed(get("epss", offline=offline))

    cvss_map = cvss_map_from_feed(get("nvd-cve", offline=offline))

    # Keep only requested ids when we have them (EPSS/NVD windows can be broad).
    if ids:
        idset = set(ids)
        epss_map = {k: v for k, v in epss_map.items() if k in idset} or epss_map
        cvss_map = {k: v for k, v in cvss_map.items() if k in idset} or cvss_map

    return kev_set, epss_map, cvss_map
