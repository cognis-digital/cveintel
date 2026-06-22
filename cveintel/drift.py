"""Posture-drift detection for cveintel: ``diff`` two scan snapshots.

The single most actionable question a vulnerability-management or SOC team
asks is not "what is my exposure today?" but **"what *changed* since the last
look, and which of those changes newly demands attention?"**. A nightly scan
of a fleet can hold thousands of CVEs; the handful that matter on any given day
are the ones that *drifted*:

    * a CVE that newly landed on the CISA KEV catalog (proven in-the-wild
      exploitation) - the single highest-signal early-warning event;
    * a CVE whose EPSS exploitation probability *spiked* (weaponization /
      public PoC / mass-scanning often precede KEV listing by days);
    * a CVE whose NVD CVSS base score was *revised upward* on reanalysis;
    * a CVE that crossed a triage-*tier* boundary (e.g. MED -> CRITICAL);
    * CVEs that newly *appeared* in scope (new asset, new finding);
    * CVEs that *disappeared* (remediated / decommissioned) - useful for
      confirming that a patch campaign actually closed what it claimed to.

This module is pure and deterministic: it diffs two already-scored snapshots
and classifies every change. No network, no clock - the same two inputs always
produce the same drift report, which makes it safe to gate CI on and trivial to
test offline.

DEFENSIVE USE ONLY. This is situational-awareness / early-warning tooling: it
tells a defender *what got worse* so they can re-prioritize remediation. It
contains no exploitation, targeting, or offensive capability of any kind.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from .scoring import TIER_ORDER, ScoredCVE, rank_records, score_record

# A change in EPSS at or above this absolute delta is treated as a "spike"
# worth surfacing on its own. EPSS is a 0..1 probability, so 0.10 == a 10
# percentage-point jump in modeled 30-day exploitation likelihood.
EPSS_SPIKE_DELTA = 0.10

# A CVSS base-score revision at or above this magnitude is surfaced. NVD
# reanalysis routinely nudges scores by 0.1-0.2; a >= 1.0 swing is material.
CVSS_REVISION_DELTA = 1.0

# Tolerance so that a delta *equal* to a threshold still trips it despite
# binary floating-point representation error (e.g. 0.4 - 0.5 == -0.0999...).
_EPS = 1e-9

# Kinds of drift, ordered most- to least-urgent for stable sorting / display.
DRIFT_KIND_ORDER = {
    "kev_added": 0,        # newly known-exploited - act now
    "tier_up": 1,          # crossed a triage boundary upward
    "epss_spike": 2,       # exploitation probability jumped
    "cvss_up": 3,          # base severity revised upward
    "appeared": 4,         # new in scope
    "cvss_down": 5,        # base severity revised downward
    "epss_drop": 6,        # exploitation probability fell
    "tier_down": 7,        # de-escalated
    "kev_removed": 8,      # removed from KEV (rare; catalog correction)
    "resolved": 9,         # disappeared from scope (remediated)
}


@dataclass
class DriftItem:
    """One classified change for a single CVE between two snapshots."""

    cve_id: str
    kinds: list[str] = field(default_factory=list)
    before: Optional[dict] = None  # ScoredCVE.to_dict() or None if new
    after: Optional[dict] = None   # ScoredCVE.to_dict() or None if resolved
    notes: list[str] = field(default_factory=list)

    @property
    def severity_rank(self) -> int:
        """Lower is more urgent; the most-urgent kind drives the ordering."""
        return min((DRIFT_KIND_ORDER.get(k, 99) for k in self.kinds), default=99)

    @property
    def worsened(self) -> bool:
        """True if any change makes the posture *worse* (defender-relevant)."""
        worse = {"kev_added", "tier_up", "epss_spike", "cvss_up", "appeared"}
        return any(k in worse for k in self.kinds)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "kinds": list(self.kinds),
            "worsened": self.worsened,
            "before": self.before,
            "after": self.after,
            "notes": list(self.notes),
        }


def _index(scored: Iterable[ScoredCVE]) -> dict[str, ScoredCVE]:
    """Map cve_id -> ScoredCVE, keeping the highest-scoring on duplicates."""
    out: dict[str, ScoredCVE] = {}
    for s in scored:
        prev = out.get(s.cve_id)
        if prev is None or s.score > prev.score:
            out[s.cve_id] = s
    return out


def _classify(before: Optional[ScoredCVE], after: Optional[ScoredCVE]) -> DriftItem:
    cid = (after or before).cve_id  # type: ignore[union-attr]
    kinds: list[str] = []
    notes: list[str] = []

    if before is None and after is not None:
        kinds.append("appeared")
        notes.append(f"new in scope at {after.tier} (score {after.score})")
        if after.kev:
            kinds.append("kev_added")
            notes.append("appeared already on CISA KEV - actively exploited")
        return DriftItem(cid, kinds, None, after.to_dict(), notes)

    if after is None and before is not None:
        kinds.append("resolved")
        notes.append(f"no longer in scope (was {before.tier})")
        return DriftItem(cid, kinds, before.to_dict(), None, notes)

    assert before is not None and after is not None

    # KEV transitions - the headline early-warning signal.
    if after.kev and not before.kev:
        kinds.append("kev_added")
        notes.append("newly listed on CISA KEV - proven in-the-wild exploitation")
    elif before.kev and not after.kev:
        kinds.append("kev_removed")
        notes.append("removed from CISA KEV (catalog correction)")

    # Tier crossing.
    tb, ta = TIER_ORDER[before.tier], TIER_ORDER[after.tier]
    if ta > tb:
        kinds.append("tier_up")
        notes.append(f"tier escalated {before.tier} -> {after.tier}")
    elif ta < tb:
        kinds.append("tier_down")
        notes.append(f"tier de-escalated {before.tier} -> {after.tier}")

    # EPSS movement.
    if before.epss is not None and after.epss is not None:
        d = after.epss - before.epss
        if d >= EPSS_SPIKE_DELTA - _EPS:
            kinds.append("epss_spike")
            notes.append(
                f"EPSS spiked {before.epss:.2f} -> {after.epss:.2f} "
                f"(+{d * 100:.0f} pts) - rising exploitation likelihood"
            )
        elif d <= -EPSS_SPIKE_DELTA + _EPS:
            kinds.append("epss_drop")
            notes.append(f"EPSS fell {before.epss:.2f} -> {after.epss:.2f}")
    elif before.epss is None and after.epss is not None and after.epss >= EPSS_SPIKE_DELTA:
        kinds.append("epss_spike")
        notes.append(f"EPSS now scored at {after.epss:.2f} (was unscored)")

    # CVSS revision (NVD reanalysis).
    if before.cvss is not None and after.cvss is not None:
        d = after.cvss - before.cvss
        if d >= CVSS_REVISION_DELTA - _EPS:
            kinds.append("cvss_up")
            notes.append(f"CVSS revised up {before.cvss:.1f} -> {after.cvss:.1f}")
        elif d <= -CVSS_REVISION_DELTA + _EPS:
            kinds.append("cvss_down")
            notes.append(f"CVSS revised down {before.cvss:.1f} -> {after.cvss:.1f}")
    elif before.cvss is None and after.cvss is not None:
        kinds.append("cvss_up")
        notes.append(f"CVSS now scored {after.cvss:.1f} (was unscored)")

    return DriftItem(cid, kinds, before.to_dict(), after.to_dict(), notes)


def diff_scored(
    before: Iterable[ScoredCVE],
    after: Iterable[ScoredCVE],
    *,
    worsened_only: bool = False,
) -> list[DriftItem]:
    """Diff two scored snapshots, returning classified, sorted drift items.

    Items are sorted most-urgent first: by the most-urgent drift kind, then by
    the *current* (after) composite score descending, then CVE id for
    stability. Unchanged CVEs are omitted entirely.

    ``worsened_only`` keeps only changes that make the posture worse (KEV add,
    tier escalation, EPSS spike, CVSS-up, newly-appeared) - the default-deny
    view a defender wants on a CI gate.
    """
    bi = _index(before)
    ai = _index(after)

    items: list[DriftItem] = []
    for cid in set(bi) | set(ai):
        item = _classify(bi.get(cid), ai.get(cid))
        if not item.kinds:
            continue  # present in both, nothing changed
        if worsened_only and not item.worsened:
            continue
        items.append(item)

    def _after_score(it: DriftItem) -> float:
        return (it.after or {}).get("score", -1.0) if it.after else -1.0

    items.sort(key=lambda it: (it.severity_rank, -_after_score(it), it.cve_id))
    return items


def diff_records(
    before_records: list[dict],
    after_records: list[dict],
    *,
    worsened_only: bool = False,
) -> list[DriftItem]:
    """Score two enriched record lists, then diff them. Convenience wrapper."""
    before = [score_record(r) for r in before_records]
    after = [score_record(r) for r in after_records]
    return diff_scored(before, after, worsened_only=worsened_only)


def summarize(items: Iterable[DriftItem]) -> dict:
    """Aggregate drift items into a small headline summary dict."""
    items = list(items)
    counts: dict[str, int] = {}
    for it in items:
        for k in it.kinds:
            counts[k] = counts.get(k, 0) + 1
    worsened = [it for it in items if it.worsened]
    return {
        "total_changed": len(items),
        "worsened": len(worsened),
        "kev_added": counts.get("kev_added", 0),
        "tier_up": counts.get("tier_up", 0),
        "epss_spike": counts.get("epss_spike", 0),
        "appeared": counts.get("appeared", 0),
        "resolved": counts.get("resolved", 0),
        "counts": counts,
    }


# Drift kinds that count as "the posture got worse" for the CI gate.
WORSENED_KINDS = {"kev_added", "tier_up", "epss_spike", "cvss_up", "appeared"}
