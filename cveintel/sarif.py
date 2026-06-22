"""SARIF 2.1.0 export for cveintel rankings.

Emits a `Static Analysis Results Interchange Format
<https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>`_ log so a
cveintel ranking can be uploaded straight into GitHub code-scanning, Azure
DevOps, or any SARIF-aware dashboard. Standard library only.

Mapping
-------
- Each scored CVE becomes one ``result``; the CVE id is the ``ruleId`` and a
  matching reporting descriptor (rule) is emitted under the tool driver.
- The composite tier maps to the SARIF ``level``:
  CRITICAL/HIGH -> ``error``, MED -> ``warning``, LOW -> ``note``.
- The composite 0-100 score is carried as a ``rank`` (0-100, SARIF's own
  prioritization field) and the raw signals are attached as result
  ``properties`` so nothing is lost.
- The plain-language ``reasons`` are joined into the result message.
"""

from __future__ import annotations

from typing import Iterable

from . import __version__

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

# Triage tier -> SARIF result level.
_TIER_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MED": "warning",
    "LOW": "note",
}


def _level_for(tier: str) -> str:
    return _TIER_LEVEL.get(tier.upper(), "none")


def to_sarif(scored: Iterable, *, tool_name: str = "cveintel") -> dict:
    """Build a SARIF 2.1.0 log object from an iterable of ``ScoredCVE``.

    The argument is whatever :func:`cveintel.scoring.rank_records` returns;
    each element must expose ``cve_id``, ``cvss``, ``epss``, ``kev``,
    ``score``, ``tier``, ``description`` and ``reasons``.
    """
    scored = list(scored)

    rules: list[dict] = []
    seen_rules: set[str] = set()
    results: list[dict] = []

    for s in scored:
        if s.cve_id not in seen_rules:
            seen_rules.add(s.cve_id)
            rule: dict = {
                "id": s.cve_id,
                "name": s.cve_id.replace("-", ""),
                "shortDescription": {
                    "text": s.description or f"{s.cve_id} priority finding"
                },
                "helpUri": f"https://nvd.nist.gov/vuln/detail/{s.cve_id}",
                "properties": {
                    "tags": ["security", "cve", f"tier:{s.tier.lower()}"],
                    "kev": bool(s.kev),
                },
            }
            rules.append(rule)

        message = "; ".join(s.reasons) if s.reasons else f"{s.cve_id} ({s.tier})"
        result: dict = {
            "ruleId": s.cve_id,
            "level": _level_for(s.tier),
            "rank": float(s.score),
            "message": {"text": message},
            "properties": {
                "tier": s.tier,
                "score": s.score,
                "cvss": s.cvss,
                "epss": s.epss,
                "kev": bool(s.kev),
            },
            # No source-file location: a CVE ranking is not file-scoped, so we
            # attach a logical location naming the CVE instead.
            "locations": [
                {
                    "logicalLocations": [
                        {"name": s.cve_id, "kind": "namespace"}
                    ]
                }
            ],
        }
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": __version__,
                        "informationUri": "https://github.com/cognis-digital/cveintel",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
