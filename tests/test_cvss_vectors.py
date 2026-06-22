"""Reference-value tests for the CVSS v3.x vector base-score computation.

Values cross-checked against the FIRST.org CVSS v3.1 calculator / NVD.
"""

from __future__ import annotations

import pytest

from cveintel.vulnmatch import cvss_vector_base_score


@pytest.mark.parametrize(
    "vector,expected",
    [
        # Log4Shell (CVE-2021-44228)
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        # AV:N integrity-only high (e.g. prototype pollution class)
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 7.5),
        # Full confidentiality breach, no scope change
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        # Local, high complexity, low availability impact -> low
        ("CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", 2.9),
        # Network DoS (availability only)
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        # No impact -> 0
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        # Classic full-CIA RCE (CVE-2017-5638-ish), scope unchanged
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ],
)
def test_known_vectors(vector, expected):
    assert cvss_vector_base_score(vector) == pytest.approx(expected, abs=0.05)


def test_unknown_version_falls_through():
    assert cvss_vector_base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P") is None


def test_garbage_returns_none():
    assert cvss_vector_base_score("not a vector") is None


def test_privileges_required_lowers_score():
    high = cvss_vector_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    low = cvss_vector_base_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")
    assert low < high


def test_user_interaction_lowers_score():
    no_ui = cvss_vector_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    req_ui = cvss_vector_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
    assert req_ui < no_ui


def test_local_lower_than_network():
    net = cvss_vector_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    loc = cvss_vector_base_score("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert loc < net


def test_all_scores_in_range():
    import itertools

    metrics = {
        "AV": "NALP",
        "AC": "LH",
        "PR": "NLH",
        "UI": "NR",
        "S": "UC",
        "C": "NLH",
        "I": "NLH",
        "A": "NLH",
    }
    keys = list(metrics)
    # sample a subset to keep it fast
    combos = itertools.islice(
        itertools.product(*[metrics[k] for k in keys]), 0, 400, 7
    )
    for combo in combos:
        vec = "CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in zip(keys, combo))
        score = cvss_vector_base_score(vec)
        assert score is None or (0.0 <= score <= 10.0)
