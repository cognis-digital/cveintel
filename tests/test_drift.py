"""Tests for posture-drift detection (cveintel.drift).

Pure, offline, deterministic: every test diffs two in-memory snapshots and
asserts the classification, ordering, summary, and gate semantics.
"""

import pytest

from cveintel.drift import (
    CVSS_REVISION_DELTA,
    DRIFT_KIND_ORDER,
    EPSS_SPIKE_DELTA,
    WORSENED_KINDS,
    DriftItem,
    diff_records,
    diff_scored,
    summarize,
)
from cveintel.scoring import score_record


# --- helpers --------------------------------------------------------------


def rec(cid, cvss=None, epss=None, kev=False):
    return {"cve_id": cid, "cvss": cvss, "epss": epss, "kev": kev}


def kinds_for(items, cid):
    for it in items:
        if it.cve_id == cid:
            return set(it.kinds)
    return None


def get(items, cid):
    return next((it for it in items if it.cve_id == cid), None)


# --- appeared / resolved --------------------------------------------------


def test_appeared_is_flagged():
    before = []
    after = [rec("CVE-2024-0001", 9.0, 0.5, False)]
    items = diff_records(before, after)
    assert kinds_for(items, "CVE-2024-0001") == {"appeared"}


def test_appeared_already_kev_stacks_kev_added():
    items = diff_records([], [rec("CVE-2024-0001", 9.0, 0.5, True)])
    assert kinds_for(items, "CVE-2024-0001") == {"appeared", "kev_added"}


def test_resolved_is_flagged():
    before = [rec("CVE-2024-0001", 9.0, 0.5, False)]
    items = diff_records(before, [])
    assert kinds_for(items, "CVE-2024-0001") == {"resolved"}


def test_resolved_is_not_worsened():
    items = diff_records([rec("CVE-2024-0001", 9.0, 0.5, False)], [])
    assert get(items, "CVE-2024-0001").worsened is False


def test_appeared_is_worsened():
    items = diff_records([], [rec("CVE-2024-0001", 9.0, 0.5, False)])
    assert get(items, "CVE-2024-0001").worsened is True


# --- KEV transitions ------------------------------------------------------


def test_kev_added():
    before = [rec("CVE-2024-0001", 7.5, 0.2, False)]
    after = [rec("CVE-2024-0001", 7.5, 0.2, True)]
    assert "kev_added" in kinds_for(after_items := diff_records(before, after), "CVE-2024-0001")
    assert after_items[0].worsened is True


def test_kev_removed():
    before = [rec("CVE-2024-0001", 7.5, 0.2, True)]
    after = [rec("CVE-2024-0001", 7.5, 0.2, False)]
    k = kinds_for(diff_records(before, after), "CVE-2024-0001")
    assert "kev_removed" in k


def test_kev_removed_not_worsened():
    before = [rec("CVE-2024-0001", 7.5, 0.2, True)]
    after = [rec("CVE-2024-0001", 7.5, 0.2, False)]
    # KEV removal de-escalates the score (tier_down) but is not "worsened".
    it = get(diff_records(before, after), "CVE-2024-0001")
    assert it.worsened is False


# --- tier crossings -------------------------------------------------------


def test_tier_escalation():
    # MED -> CRITICAL via KEV+EPSS jump
    before = [rec("CVE-2024-0001", 7.5, 0.10, False)]
    after = [rec("CVE-2024-0001", 7.5, 0.90, True)]
    k = kinds_for(diff_records(before, after), "CVE-2024-0001")
    assert "tier_up" in k


def test_tier_deescalation():
    before = [rec("CVE-2024-0001", 7.5, 0.90, True)]
    after = [rec("CVE-2024-0001", 7.5, 0.10, False)]
    k = kinds_for(diff_records(before, after), "CVE-2024-0001")
    assert "tier_down" in k


def test_no_tier_change_when_score_stable_within_tier():
    before = [rec("CVE-2024-0001", 5.0, 0.10, False)]
    after = [rec("CVE-2024-0001", 5.1, 0.10, False)]  # tiny CVSS move, same tier
    it = get(diff_records(before, after), "CVE-2024-0001")
    # no tier change, sub-threshold CVSS move -> no drift recorded at all
    assert it is None


# --- EPSS movement --------------------------------------------------------


def test_epss_spike_at_threshold():
    before = [rec("CVE-2024-0001", 5.0, 0.20, False)]
    after = [rec("CVE-2024-0001", 5.0, 0.20 + EPSS_SPIKE_DELTA, False)]
    assert "epss_spike" in kinds_for(diff_records(before, after), "CVE-2024-0001")


def test_epss_below_threshold_not_spike():
    # Choose CVSS so a small EPSS bump cannot cross a tier boundary: at
    # CVSS 0 the score = 40*epss, so 0.50->0.59 stays comfortably in MED.
    before = [rec("CVE-2024-0001", 0.0, 0.50, False)]
    after = [rec("CVE-2024-0001", 0.0, 0.50 + EPSS_SPIKE_DELTA - 0.01, False)]
    it = get(diff_records(before, after), "CVE-2024-0001")
    # sub-threshold EPSS move, no tier change -> nothing recorded
    assert it is None


def test_epss_drop():
    before = [rec("CVE-2024-0001", 5.0, 0.80, False)]
    after = [rec("CVE-2024-0001", 5.0, 0.50, False)]
    assert "epss_drop" in kinds_for(diff_records(before, after), "CVE-2024-0001")


def test_epss_newly_scored_from_none_counts_as_spike():
    before = [rec("CVE-2024-0001", 5.0, None, False)]
    after = [rec("CVE-2024-0001", 5.0, 0.40, False)]
    assert "epss_spike" in kinds_for(diff_records(before, after), "CVE-2024-0001")


def test_epss_newly_scored_below_threshold_no_spike():
    before = [rec("CVE-2024-0001", 5.0, None, False)]
    after = [rec("CVE-2024-0001", 5.0, 0.02, False)]
    it = get(diff_records(before, after), "CVE-2024-0001")
    assert it is None


# --- CVSS revision --------------------------------------------------------


def test_cvss_revised_up():
    before = [rec("CVE-2024-0001", 5.0, 0.10, False)]
    after = [rec("CVE-2024-0001", 5.0 + CVSS_REVISION_DELTA, 0.10, False)]
    assert "cvss_up" in kinds_for(diff_records(before, after), "CVE-2024-0001")


def test_cvss_revised_down():
    before = [rec("CVE-2024-0001", 8.0, 0.10, False)]
    after = [rec("CVE-2024-0001", 6.0, 0.10, False)]
    assert "cvss_down" in kinds_for(diff_records(before, after), "CVE-2024-0001")


def test_cvss_newly_scored_from_none():
    before = [rec("CVE-2024-0001", None, 0.10, False)]
    after = [rec("CVE-2024-0001", 7.5, 0.10, False)]
    assert "cvss_up" in kinds_for(diff_records(before, after), "CVE-2024-0001")


def test_cvss_minor_revision_below_threshold_ignored():
    before = [rec("CVE-2024-0001", 7.5, 0.10, False)]
    after = [rec("CVE-2024-0001", 7.6, 0.10, False)]
    it = get(diff_records(before, after), "CVE-2024-0001")
    assert it is None


# --- multiple kinds stack -------------------------------------------------


def test_multiple_drift_kinds_stack_on_one_item():
    before = [rec("CVE-2024-0001", 5.0, 0.10, False)]
    after = [rec("CVE-2024-0001", 9.8, 0.90, True)]
    k = kinds_for(diff_records(before, after), "CVE-2024-0001")
    assert {"kev_added", "tier_up", "epss_spike", "cvss_up"} <= k


# --- unchanged omitted ----------------------------------------------------


def test_unchanged_cve_is_omitted():
    same = [rec("CVE-2024-0001", 7.5, 0.30, True)]
    assert diff_records(same, list(same)) == []


def test_identical_snapshots_produce_empty_diff():
    snap = [
        rec("CVE-2024-0001", 9.8, 0.9, True),
        rec("CVE-2024-0002", 5.0, 0.1, False),
    ]
    assert diff_records(snap, [dict(r) for r in snap]) == []


# --- ordering -------------------------------------------------------------


def test_ordering_most_urgent_first():
    before = [
        rec("CVE-A", 9.0, 0.50, False),
        rec("CVE-B", 5.0, 0.10, False),
    ]
    after = [
        rec("CVE-A", 9.0, 0.50, True),    # kev_added (rank 0)
        rec("CVE-B", 8.0, 0.10, False),   # cvss_up (rank 3)
        rec("CVE-C", 9.9, 0.95, True),    # appeared+kev (rank 0, higher score)
    ]
    items = diff_records(before, after)
    # kev_added items come before cvss_up; among kev items higher after-score first
    assert items[0].cve_id in {"CVE-A", "CVE-C"}
    assert items[-1].cve_id == "CVE-B"


def test_ordering_is_stable_and_deterministic():
    before = [rec(f"CVE-{i:04d}", 5.0, 0.1, False) for i in range(5)]
    after = [rec(f"CVE-{i:04d}", 5.0, 0.5, False) for i in range(5)]
    a = [it.cve_id for it in diff_records(before, after)]
    b = [it.cve_id for it in diff_records(before, after)]
    assert a == b


# --- worsened_only filter -------------------------------------------------


def test_worsened_only_drops_resolved_and_drops():
    before = [
        rec("CVE-WORSE", 5.0, 0.10, False),
        rec("CVE-GONE", 5.0, 0.10, False),
        rec("CVE-BETTER", 9.0, 0.90, True),
    ]
    after = [
        rec("CVE-WORSE", 5.0, 0.90, True),   # worsened
        # CVE-GONE removed -> resolved (not worsened)
        rec("CVE-BETTER", 5.0, 0.10, False),  # de-escalated (not worsened)
    ]
    items = diff_records(before, after, worsened_only=True)
    ids = {it.cve_id for it in items}
    assert ids == {"CVE-WORSE"}


def test_worsened_only_keeps_appeared():
    items = diff_records([], [rec("CVE-NEW", 9.0, 0.5, False)], worsened_only=True)
    assert {it.cve_id for it in items} == {"CVE-NEW"}


# --- summary --------------------------------------------------------------


def test_summary_counts():
    before = [
        rec("CVE-1", 5.0, 0.10, False),
        rec("CVE-2", 5.0, 0.10, False),
        rec("CVE-3", 9.0, 0.90, True),
    ]
    after = [
        rec("CVE-1", 5.0, 0.90, True),    # kev_added, tier_up, epss_spike
        rec("CVE-2", 5.0, 0.10, False),   # unchanged
        # CVE-3 resolved
        rec("CVE-4", 9.9, 0.95, True),    # appeared+kev
    ]
    items = diff_records(before, after)
    s = summarize(items)
    assert s["total_changed"] == 3   # CVE-1, CVE-3(resolved), CVE-4
    assert s["kev_added"] == 2
    assert s["tier_up"] == 1
    assert s["epss_spike"] == 1
    assert s["appeared"] == 1
    assert s["resolved"] == 1
    assert s["worsened"] == 2  # CVE-1 and CVE-4


def test_summary_empty():
    s = summarize([])
    assert s["total_changed"] == 0
    assert s["worsened"] == 0
    assert s["counts"] == {}


# --- DriftItem semantics --------------------------------------------------


def test_driftitem_severity_rank_uses_most_urgent_kind():
    it = DriftItem("CVE-X", kinds=["cvss_up", "kev_added"])
    assert it.severity_rank == DRIFT_KIND_ORDER["kev_added"]


def test_driftitem_to_dict_roundtrip_keys():
    items = diff_records([], [rec("CVE-1", 9.8, 0.95, True)])
    d = items[0].to_dict()
    assert set(d) == {"cve_id", "kinds", "worsened", "before", "after", "notes"}
    assert d["before"] is None
    assert d["after"]["tier"] == "CRITICAL"


def test_worsened_kinds_constant_matches_property():
    # Every worsened kind, applied alone, must mark the item worsened.
    for kind in WORSENED_KINDS:
        assert DriftItem("CVE-X", kinds=[kind]).worsened is True


# --- diff_scored accepts ScoredCVE directly -------------------------------


def test_diff_scored_with_scored_objects():
    before = [score_record(rec("CVE-1", 7.5, 0.2, False))]
    after = [score_record(rec("CVE-1", 7.5, 0.2, True))]
    items = diff_scored(before, after)
    assert "kev_added" in items[0].kinds


# --- duplicate handling ---------------------------------------------------


def test_duplicate_cve_keeps_highest_scoring():
    before = [rec("CVE-1", 1.0, 0.0, False)]
    after = [
        rec("CVE-1", 1.0, 0.0, False),
        rec("CVE-1", 9.8, 0.9, True),  # higher score should win
    ]
    items = diff_records(before, after)
    it = get(items, "CVE-1")
    assert it.after["kev"] is True
    assert it.after["cvss"] == 9.8


# --- notes are populated --------------------------------------------------


def test_notes_present_for_worsened():
    items = diff_records(
        [rec("CVE-1", 5.0, 0.1, False)], [rec("CVE-1", 9.8, 0.9, True)]
    )
    notes = get(items, "CVE-1").notes
    assert notes
    assert any("KEV" in n for n in notes)


# --- empty / degenerate inputs --------------------------------------------


def test_both_empty():
    assert diff_records([], []) == []


def test_before_empty_all_appeared():
    after = [rec("CVE-1", 9.0, 0.5, False), rec("CVE-2", 5.0, 0.1, True)]
    items = diff_records([], after)
    assert all("appeared" in it.kinds for it in items)
    assert len(items) == 2


def test_after_empty_all_resolved():
    before = [rec("CVE-1", 9.0, 0.5, False), rec("CVE-2", 5.0, 0.1, True)]
    items = diff_records(before, [])
    assert all(it.kinds == ["resolved"] for it in items)
    assert len(items) == 2


# --- exact boundary deltas ------------------------------------------------


def test_cvss_revision_exactly_at_threshold_counts():
    before = [rec("CVE-1", 5.0, 0.1, False)]
    after = [rec("CVE-1", 5.0 + CVSS_REVISION_DELTA, 0.1, False)]
    assert "cvss_up" in kinds_for(diff_records(before, after), "CVE-1")


def test_epss_drop_exactly_at_threshold_counts():
    before = [rec("CVE-1", 0.0, 0.50, False)]
    after = [rec("CVE-1", 0.0, 0.50 - EPSS_SPIKE_DELTA, False)]
    assert "epss_drop" in kinds_for(diff_records(before, after), "CVE-1")


# --- summary counts key is exhaustive -------------------------------------


def test_summary_counts_dict_only_has_present_kinds():
    items = diff_records([], [rec("CVE-1", 9.0, 0.5, False)])
    s = summarize(items)
    assert s["counts"] == {"appeared": 1}


def test_worsened_count_excludes_pure_deescalation():
    before = [rec("CVE-1", 9.8, 0.95, True)]
    after = [rec("CVE-1", 1.0, 0.0, False)]  # big de-escalation
    s = summarize(diff_records(before, after))
    assert s["worsened"] == 0


# --- DRIFT_KIND_ORDER integrity -------------------------------------------


def test_kev_added_is_most_urgent_kind():
    assert DRIFT_KIND_ORDER["kev_added"] == min(DRIFT_KIND_ORDER.values())


def test_all_classifiable_kinds_have_an_order():
    produced = set()
    # exercise a spread of transitions to collect every kind emitted
    transitions = [
        ([], [rec("a", 9, 0.5, True)]),                       # appeared, kev_added
        ([rec("b", 5, 0.1, False)], []),                      # resolved
        ([rec("c", 5, 0.1, False)], [rec("c", 5, 0.9, True)]),# kev/tier/epss up
        ([rec("d", 8, 0.9, True)], [rec("d", 5, 0.1, False)]),# kev_removed/tier/epss down
        ([rec("e", 5, 0.1, False)], [rec("e", 9, 0.1, False)]),# cvss_up
        ([rec("f", 9, 0.1, False)], [rec("f", 5, 0.1, False)]),# cvss_down
    ]
    for b, a in transitions:
        for it in diff_records(b, a):
            produced.update(it.kinds)
    assert produced <= set(DRIFT_KIND_ORDER)
    assert produced  # sanity: we actually produced some kinds
