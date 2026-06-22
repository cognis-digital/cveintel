"""Passive vulnerability matching against the bundled offline vuln DB.

Wires :mod:`cveintel.vulndb_local` (the ~262k-record bundled OSV corpus) into
cveintel's enrichment so that, with *no network*, the tool can:

  * resolve a bare CVE id to a severity / summary from the local corpus
    (filling missing CVSS when an NVD fixture/feed is absent), and
  * map a software-bill-of-materials (SBOM) / package list to the CVEs that
    affect those packages.

Everything here is **passive**: it only reads provided input and the bundled,
offline database. No sockets, no live host contact. The active (consented,
authorization-gated) probe lives in :mod:`cveintel.active` and never imports
network code into this module.

Severity parsing
----------------
OSV severity strings are heterogeneous (CVSS vectors, bare scores, or empty).
:func:`severity_to_cvss` extracts a best-effort numeric CVSS base score so the
existing scoring model can rank corpus-derived findings consistently.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional

from .vulndb_local import VulnDB

# CVSS v3.x base-score is not embedded in the vector string, so when only a
# vector is present we fall back to a coarse severity word -> score map. Real
# numeric scores (when the corpus carries them) always take precedence.
_SEVERITY_WORD = {
    "critical": 9.5,
    "high": 8.0,
    "moderate": 5.5,
    "medium": 5.5,
    "low": 3.0,
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def severity_to_cvss(severity: object) -> Optional[float]:
    """Best-effort extraction of a numeric CVSS base score from OSV severity.

    Accepts a bare number ("9.8"), a severity word ("HIGH"), or a list of OSV
    severity dicts (``[{"type": "CVSS_V3", "score": "..."}]``). Returns ``None``
    when nothing numeric/known can be derived.
    """
    if severity is None:
        return None

    if isinstance(severity, (int, float)):
        return _clamp_cvss(float(severity))

    if isinstance(severity, list):
        for entry in severity:
            if isinstance(entry, dict):
                got = severity_to_cvss(entry.get("score"))
                if got is not None:
                    return got
        return None

    if isinstance(severity, dict):
        return severity_to_cvss(severity.get("score"))

    text = str(severity).strip()
    if not text:
        return None

    # Bare numeric ("9.8").
    try:
        return _clamp_cvss(float(text))
    except ValueError:
        pass

    # CVSS v3.x / v4.0 vector string -> computed base score.
    if text.upper().startswith("CVSS:"):
        got = cvss_vector_base_score(text)
        if got is not None:
            return got

    # Severity word.
    word = text.lower()
    if word in _SEVERITY_WORD:
        return _SEVERITY_WORD[word]

    # CVSS vector with an embedded numeric (rare); pull a trailing number.
    m = re.search(r"(\d+(?:\.\d+)?)\s*$", text)
    if m:
        try:
            return _clamp_cvss(float(m.group(1)))
        except ValueError:
            return None
    return None


# --- CVSS v3.1 base-score computation (per FIRST.org spec) ----------------
_V3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},   # when Scope Unchanged
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},    # when Scope Changed
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    """CVSS spec roundup: smallest one-decimal value >= x."""
    import math

    return math.ceil(x * 10.0) / 10.0


def cvss_vector_base_score(vector: str) -> Optional[float]:
    """Compute a CVSS v3.0/v3.1 base score from its vector string.

    For CVSS v4.0 vectors (which use a different, table-driven model) this
    returns a coarse approximation derived from the vulnerable-system impact
    metrics, which is adequate for ranking. Returns ``None`` if required base
    metrics are absent.
    """
    parts = {}
    for chunk in vector.split("/"):
        if ":" in chunk:
            k, v = chunk.split(":", 1)
            parts[k.strip().upper()] = v.strip().upper()

    version = parts.get("CVSS", "")

    if version.startswith("4"):
        return _cvss4_approx(parts)

    try:
        av = _V3_WEIGHTS["AV"][parts["AV"]]
        ac = _V3_WEIGHTS["AC"][parts["AC"]]
        ui = _V3_WEIGHTS["UI"][parts["UI"]]
        scope_changed = parts["S"] == "C"
        pr_table = _V3_WEIGHTS["PR_C"] if scope_changed else _V3_WEIGHTS["PR_U"]
        pr = pr_table[parts["PR"]]
        c = _V3_WEIGHTS["CIA"][parts["C"]]
        i = _V3_WEIGHTS["CIA"][parts["I"]]
        a = _V3_WEIGHTS["CIA"][parts["A"]]
    except KeyError:
        return None

    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)
    return _clamp_cvss(_roundup(base))


def _cvss4_approx(parts: dict) -> Optional[float]:
    """Coarse CVSS v4.0 approximation from vulnerable-system impact + AV.

    v4.0's true scoring is a large lookup table; for *ranking* purposes a
    monotonic approximation from impact severity is sufficient and avoids
    shipping the full table. Conservative (never overstates critical).
    """
    impact_keys = ("VC", "VI", "VA")
    sev = {"H": 1.0, "L": 0.5, "N": 0.0}
    vals = [sev.get(parts.get(k, "N"), 0.0) for k in impact_keys]
    if not any(k in parts for k in impact_keys):
        return None
    impact = max(vals)
    breadth = sum(vals) / 3.0
    av = {"N": 1.0, "A": 0.8, "L": 0.65, "P": 0.45}.get(parts.get("AV", "N"), 0.7)
    # Scale to a 0-10 range biased by attack vector and impact breadth.
    score = 10.0 * (0.55 * impact + 0.25 * breadth + 0.20 * av * impact)
    return _clamp_cvss(round(min(score, 10.0), 1))


def _clamp_cvss(value: float) -> Optional[float]:
    if value < 0:
        return None
    if value > 10.0:
        return None
    return round(value, 1)


def best_record_cvss(records: Iterable[dict]) -> Optional[float]:
    """Highest derivable CVSS across a set of corpus records (or None)."""
    best: Optional[float] = None
    for r in records:
        got = severity_to_cvss(r.get("severity"))
        if got is not None and (best is None or got > best):
            best = got
    return best


def cve_to_cvss_map(cve_ids: Iterable[str], db: Optional[VulnDB] = None) -> dict[str, float]:
    """Map CVE id -> best-effort CVSS from the bundled corpus.

    Only ids that resolve to a numeric severity are included; this is used to
    *fill* a missing CVSS without overriding authoritative NVD data.
    """
    db = db or VulnDB()
    out: dict[str, float] = {}
    for cid in cve_ids:
        if not cid:
            continue
        recs = db.by_cve(cid)
        if not recs:
            continue
        cvss = best_record_cvss(recs)
        if cvss is not None:
            out[str(cid)] = cvss
    return out


def enrich_from_vulndb(records: list[dict], db: Optional[VulnDB] = None) -> list[dict]:
    """Fill missing ``cvss`` on records from the bundled offline corpus.

    Non-destructive: existing ``cvss`` values are preserved. Adds a
    ``vulndb_match`` flag and a ``vulndb_summary`` when the corpus knew the CVE.
    """
    db = db or VulnDB()
    out: list[dict] = []
    for rec in records:
        new = dict(rec)
        cid = new.get("cve_id")
        recs = db.by_cve(cid) if cid else []
        if recs:
            new["vulndb_match"] = True
            if not new.get("vulndb_summary"):
                summ = next((r.get("summary") for r in recs if r.get("summary")), "")
                if summ:
                    new["vulndb_summary"] = summ
            if new.get("cvss") is None:
                cvss = best_record_cvss(recs)
                if cvss is not None:
                    new["cvss"] = cvss
        else:
            new.setdefault("vulndb_match", False)
        out.append(new)
    return out


def load_sbom(path: str) -> list[dict]:
    """Load a software bill of materials into ``[{"name", "ecosystem"}, ...]``.

    Tolerant of several common shapes (all parsed *offline*):

      * a JSON list of package-name strings
      * a JSON list of ``{"name": ..., "ecosystem": ...}`` objects
      * CycloneDX (``{"components": [{"name", "purl"|"group"}...]}``)
      * a plain newline-delimited text file of package names
    """
    import json
    import os

    if not os.path.exists(path):
        raise FileNotFoundError(path)

    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()

    text = raw.strip()
    if not text:
        return []

    data: object
    if text[0] in "[{":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
    else:
        data = None

    if data is None:
        # newline-delimited package list
        return [
            {"name": line.strip(), "ecosystem": None}
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    if isinstance(data, dict) and "components" in data:  # CycloneDX
        comps = data.get("components") or []
        return [_component_to_pkg(c) for c in comps if isinstance(c, dict)]

    if isinstance(data, dict) and "packages" in data:  # SPDX-ish / generic
        pkgs = data.get("packages") or []
        out: list[dict] = []
        for p in pkgs:
            if isinstance(p, str):
                out.append({"name": p, "ecosystem": None})
            elif isinstance(p, dict):
                out.append(_component_to_pkg(p))
        return out

    if isinstance(data, list):
        out2: list[dict] = []
        for item in data:
            if isinstance(item, str):
                out2.append({"name": item, "ecosystem": None})
            elif isinstance(item, dict):
                out2.append(_component_to_pkg(item))
        return out2

    raise ValueError("unsupported SBOM shape")


def _component_to_pkg(c: dict) -> dict:
    name = c.get("name") or c.get("packageName") or c.get("package")
    eco = c.get("ecosystem") or c.get("type")
    purl = c.get("purl") or ""
    if purl.startswith("pkg:"):
        # pkg:npm/foo@1.2.3  ->  ecosystem npm, name foo
        try:
            scheme = purl.split(":", 1)[1]
            eco = eco or scheme.split("/", 1)[0]
            tail = scheme.split("/", 1)[1] if "/" in scheme else ""
            nm = tail.split("@", 1)[0]
            name = name or nm.rsplit("/", 1)[-1]
        except (IndexError, ValueError):
            pass
    return {"name": str(name) if name else "", "ecosystem": eco}


def scan_sbom(
    packages: list[dict],
    db: Optional[VulnDB] = None,
    ecosystem_strict: bool = False,
) -> list[dict]:
    """Match an SBOM package list to affecting CVEs from the bundled corpus.

    Returns a list of CVE *records* (cve_id/cvss/description/source package)
    suitable for handing to :func:`cveintel.scoring.rank_records`. Fully
    offline. De-duplicates on CVE id, keeping the highest-severity hit.
    """
    db = db or VulnDB()
    by_cve: dict[str, dict] = {}

    for pkg in packages:
        name = (pkg.get("name") or "").strip()
        if not name:
            continue
        eco = pkg.get("ecosystem") if ecosystem_strict else None
        hits = db.by_package(name, ecosystem=eco)
        for r in hits:
            cve_id = _record_cve_id(r)
            if not cve_id:
                continue
            cvss = severity_to_cvss(r.get("severity"))
            rec = {
                "cve_id": cve_id,
                "cvss": cvss,
                "description": r.get("summary", ""),
                "package": name,
                "ecosystem": r.get("ecosystem", ""),
                "vulndb_match": True,
            }
            prev = by_cve.get(cve_id)
            if prev is None or (cvss or -1) > (prev.get("cvss") or -1):
                by_cve[cve_id] = rec
    return list(by_cve.values())


def _record_cve_id(r: dict) -> Optional[str]:
    """Pick a CVE id from a corpus record (alias preferred, else the id)."""
    for alias in r.get("aliases") or []:
        if _CVE_RE.fullmatch(str(alias).strip()):
            return str(alias).upper()
    rid = r.get("id", "")
    m = _CVE_RE.fullmatch(str(rid).strip())
    if m:
        return str(rid).upper()
    # Fall back to the OSV id so the finding is still trackable.
    return str(rid) if rid else None
