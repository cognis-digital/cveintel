"""Scoring and prioritization model for cveintel.

The composite priority score blends three independent signals onto a 0-100
scale, then maps the score to a triage tier.

SCORING FORMULA
---------------
Three normalized inputs, each in [0, 1]:

    cvss_n  = clamp(cvss_base / 10.0, 0, 1)      # base technical severity
    epss_n  = clamp(epss, 0, 1)                    # 30-day exploitation probability
    kev     = 1.0 if CVE in CISA KEV else 0.0      # known-exploited flag

Weighted base (severity + likelihood), KEV excluded from the weights so it
acts purely as an escalator:

    base = 100 * (W_CVSS * cvss_n + W_EPSS * epss_n)

with W_CVSS = 0.6 and W_EPSS = 0.4 (sum to 1.0, so base is in [0, 100]).

KEV escalation. Known-exploited vulnerabilities are categorically more urgent
than their CVSS/EPSS alone suggest, so KEV applies a strong multiplicative
boost AND a floor:

    if kev:
        score = base + KEV_BONUS * (100 - base)    # close the gap to 100
        score = max(score, KEV_FLOOR)              # never below the floor

KEV_BONUS = 0.5 closes half the remaining distance to 100 (a moderate-base
KEV item is pulled sharply upward). KEV_FLOOR = 70 guarantees any KEV CVE
lands at least in the HIGH tier regardless of weak CVSS/EPSS data.

Final score is clamped to [0, 100] and rounded to one decimal.

TIERS
-----
    score >= 90  -> CRITICAL
    score >= 70  -> HIGH
    score >= 40  -> MED
    else         -> LOW

The model is deliberately transparent and deterministic: every points
contribution is explainable, which the `reasons()` function surfaces in
plain language.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Signal weights (must sum to 1.0 so `base` stays in [0, 100]).
W_CVSS = 0.6
W_EPSS = 0.4

# KEV escalation parameters.
KEV_BONUS = 0.5   # fraction of the gap to 100 closed when KEV-listed
KEV_FLOOR = 70.0  # minimum score for any KEV-listed CVE

# Tier thresholds (inclusive lower bounds).
TIER_CRITICAL = 90.0
TIER_HIGH = 70.0
TIER_MED = 40.0

TIER_ORDER = {"CRITICAL": 3, "HIGH": 2, "MED": 1, "LOW": 0}


def clamp(value: float, lo: float, hi: float) -> float:
    """Clamp ``value`` into the closed interval [lo, hi]."""
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


@dataclass
class ScoredCVE:
    """A CVE record with computed priority signals."""

    cve_id: str
    cvss: Optional[float]
    epss: Optional[float]
    kev: bool
    score: float
    tier: str
    description: str = ""
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "cvss": self.cvss,
            "epss": self.epss,
            "kev": self.kev,
            "score": self.score,
            "tier": self.tier,
            "description": self.description,
            "reasons": self.reasons,
        }


def tier_for(score: float) -> str:
    """Map a composite score in [0, 100] to a triage tier."""
    if score >= TIER_CRITICAL:
        return "CRITICAL"
    if score >= TIER_HIGH:
        return "HIGH"
    if score >= TIER_MED:
        return "MED"
    return "LOW"


def compute_score(
    cvss: Optional[float],
    epss: Optional[float],
    kev: bool,
) -> float:
    """Compute the composite priority score (0-100) for one CVE.

    Missing CVSS or EPSS are treated as 0 for the base calculation (absence of
    evidence is not escalated), but a KEV listing still applies its floor.
    """
    cvss_n = clamp((cvss or 0.0) / 10.0, 0.0, 1.0)
    epss_n = clamp(epss or 0.0, 0.0, 1.0)

    base = 100.0 * (W_CVSS * cvss_n + W_EPSS * epss_n)

    if kev:
        score = base + KEV_BONUS * (100.0 - base)
        score = max(score, KEV_FLOOR)
    else:
        score = base

    return round(clamp(score, 0.0, 100.0), 1)


def reasons_for(
    cvss: Optional[float],
    epss: Optional[float],
    kev: bool,
) -> list[str]:
    """Produce plain-language explanations for the score drivers."""
    out: list[str] = []

    if kev:
        out.append("in CISA KEV - actively exploited in the wild")

    if epss is not None:
        pct = epss * 100.0
        if epss >= 0.5:
            out.append(f"EPSS {epss:.2f} - high exploitation likelihood ({pct:.0f}%)")
        elif epss >= 0.1:
            out.append(f"EPSS {epss:.2f} - moderate exploitation likelihood ({pct:.0f}%)")
        else:
            out.append(f"EPSS {epss:.2f} - low exploitation likelihood ({pct:.0f}%)")

    if cvss is not None:
        if cvss >= 9.0:
            out.append(f"CVSS {cvss:.1f} - critical base severity")
        elif cvss >= 7.0:
            out.append(f"CVSS {cvss:.1f} - high base severity")
        elif cvss >= 4.0:
            out.append(f"CVSS {cvss:.1f} - medium base severity")
        else:
            out.append(f"CVSS {cvss:.1f} - low base severity")

    if not out:
        out.append("no severity, KEV, or EPSS signal available")

    return out


def score_record(record: dict) -> ScoredCVE:
    """Score a single enriched CVE record dict.

    Expected keys: ``cve_id`` (required), ``cvss``, ``epss``, ``kev``,
    ``description`` (all optional).
    """
    cve_id = record.get("cve_id") or record.get("id") or record.get("cve")
    if not cve_id:
        raise ValueError("record is missing a CVE id (cve_id / id / cve)")

    cvss = record.get("cvss")
    epss = record.get("epss")
    kev = bool(record.get("kev", False))

    cvss = float(cvss) if cvss is not None else None
    epss = float(epss) if epss is not None else None

    score = compute_score(cvss, epss, kev)
    tier = tier_for(score)
    reasons = reasons_for(cvss, epss, kev)

    return ScoredCVE(
        cve_id=str(cve_id),
        cvss=cvss,
        epss=epss,
        kev=kev,
        score=score,
        tier=tier,
        description=str(record.get("description", "")),
        reasons=reasons,
    )


def rank_records(records: list[dict]) -> list[ScoredCVE]:
    """Score and sort CVE records by descending priority.

    Ties broken by: KEV first, then CVSS, then EPSS, then CVE id (stable).
    """
    scored = [score_record(r) for r in records]
    scored.sort(
        key=lambda s: (
            s.score,
            1 if s.kev else 0,
            s.cvss or 0.0,
            s.epss or 0.0,
            s.cve_id,
        ),
        reverse=True,
    )
    return scored
