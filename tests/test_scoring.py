"""Tests for the scoring model: math, tiers, KEV escalation, ranking order."""

import math

import pytest

from cveintel.scoring import (
    KEV_FLOOR,
    compute_score,
    rank_records,
    reasons_for,
    score_record,
    tier_for,
)


def approx(a, b, tol=0.05):
    return math.isclose(a, b, abs_tol=tol)


# --- base formula --------------------------------------------------------


def test_base_no_kev_combines_cvss_and_epss():
    # base = 100 * (0.6 * (9.8/10) + 0.4 * 0.94) = 96.4
    assert approx(compute_score(9.8, 0.94, kev=False), 96.4)


def test_base_pure_cvss():
    # 100 * 0.6 * (10/10) = 60.0
    assert approx(compute_score(10.0, 0.0, kev=False), 60.0)


def test_base_pure_epss():
    # 100 * 0.4 * 1.0 = 40.0
    assert approx(compute_score(0.0, 1.0, kev=False), 40.0)


def test_zero_signals_scores_zero():
    assert compute_score(0.0, 0.0, kev=False) == 0.0


def test_missing_signals_treated_as_zero():
    assert compute_score(None, None, kev=False) == 0.0


def test_clamping_out_of_range_inputs():
    # cvss > 10 and epss > 1 must clamp, not exceed 100
    assert compute_score(15.0, 2.0, kev=False) == 100.0


# --- KEV escalation ------------------------------------------------------


def test_kev_closes_half_the_gap_to_100():
    base = compute_score(9.8, 0.94, kev=False)  # 96.4
    escalated = compute_score(9.8, 0.94, kev=True)  # 96.4 + 0.5*3.6 = 98.2
    assert escalated > base
    assert approx(escalated, 98.2)


def test_kev_floor_promotes_weak_cve_to_high():
    # Weak signals: base would be low, but KEV floor forces >= 70.
    weak = compute_score(2.0, 0.01, kev=False)
    assert weak < KEV_FLOOR
    escalated = compute_score(2.0, 0.01, kev=True)
    assert escalated >= KEV_FLOOR
    assert tier_for(escalated) == "HIGH"


def test_kev_only_no_other_signal_hits_floor():
    assert compute_score(None, None, kev=True) == KEV_FLOOR


# --- tiers ---------------------------------------------------------------


@pytest.mark.parametrize(
    "score,tier",
    [
        (100.0, "CRITICAL"),
        (90.0, "CRITICAL"),
        (89.9, "HIGH"),
        (70.0, "HIGH"),
        (69.9, "MED"),
        (40.0, "MED"),
        (39.9, "LOW"),
        (0.0, "LOW"),
    ],
)
def test_tier_boundaries(score, tier):
    assert tier_for(score) == tier


# --- record scoring ------------------------------------------------------


def test_score_record_full():
    rec = {"cve_id": "CVE-2024-10001", "cvss": 9.8, "epss": 0.94, "kev": True}
    s = score_record(rec)
    assert s.cve_id == "CVE-2024-10001"
    assert s.tier == "CRITICAL"
    assert approx(s.score, 98.2)
    assert s.kev is True


def test_score_record_accepts_alias_ids():
    s = score_record({"id": "CVE-2024-99999", "cvss": 5.0})
    assert s.cve_id == "CVE-2024-99999"


def test_score_record_requires_id():
    with pytest.raises(ValueError):
        score_record({"cvss": 5.0})


# --- reasons -------------------------------------------------------------


def test_reasons_mentions_kev_and_severity():
    reasons = reasons_for(9.8, 0.94, kev=True)
    joined = " ".join(reasons).lower()
    assert "kev" in joined
    assert "epss" in joined
    assert "cvss" in joined


def test_reasons_empty_signal():
    reasons = reasons_for(None, None, kev=False)
    assert any("no severity" in r.lower() for r in reasons)


# --- ranking order -------------------------------------------------------


def test_rank_orders_by_descending_score():
    records = [
        {"cve_id": "LOW", "cvss": 4.3, "epss": 0.01, "kev": False},
        {"cve_id": "CRIT", "cvss": 9.8, "epss": 0.94, "kev": True},
        {"cve_id": "MED", "cvss": 7.5, "epss": 0.42, "kev": False},
    ]
    ranked = rank_records(records)
    assert [r.cve_id for r in ranked] == ["CRIT", "MED", "LOW"]
    # scores strictly non-increasing
    scores = [r.score for r in ranked]
    assert scores == sorted(scores, reverse=True)


def test_kev_outranks_equal_base_non_kev():
    records = [
        {"cve_id": "NOKEV", "cvss": 7.0, "epss": 0.3, "kev": False},
        {"cve_id": "KEV", "cvss": 7.0, "epss": 0.3, "kev": True},
    ]
    ranked = rank_records(records)
    assert ranked[0].cve_id == "KEV"
