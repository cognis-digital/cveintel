//! Core cveintel priority-scoring model, ported to Rust.
//!
//! Faithful port of `cveintel/scoring.py`: blends CVSS base severity, EPSS
//! exploitation probability, and CISA KEV presence into a 0-100 priority score
//! and a triage tier. No std-external deps; no network; no exploit logic.
//! Defensive / authorized-use only.

/// CVSS weight in the base blend.
pub const W_CVSS: f64 = 0.6;
/// EPSS weight in the base blend.
pub const W_EPSS: f64 = 0.4;
/// Fraction of the gap to 100 closed when a CVE is KEV-listed.
pub const KEV_BONUS: f64 = 0.5;
/// Minimum score for any KEV-listed CVE.
pub const KEV_FLOOR: f64 = 70.0;

pub const TIER_CRITICAL: f64 = 90.0;
pub const TIER_HIGH: f64 = 70.0;
pub const TIER_MED: f64 = 40.0;

fn clamp(v: f64, lo: f64, hi: f64) -> f64 {
    if v < lo {
        lo
    } else if v > hi {
        hi
    } else {
        v
    }
}

/// Compute the composite priority score (0-100), rounded to one decimal.
///
/// `cvss` and `epss` are `Option`s so absence is distinct from a 0 value;
/// absent signals contribute 0 to the base (absence is not escalated), but a
/// KEV listing still applies its floor.
pub fn compute_score(cvss: Option<f64>, epss: Option<f64>, kev: bool) -> f64 {
    let cvss_n = clamp(cvss.unwrap_or(0.0) / 10.0, 0.0, 1.0);
    let epss_n = clamp(epss.unwrap_or(0.0), 0.0, 1.0);

    let base = 100.0 * (W_CVSS * cvss_n + W_EPSS * epss_n);

    let mut score = base;
    if kev {
        score = base + KEV_BONUS * (100.0 - base);
        if score < KEV_FLOOR {
            score = KEV_FLOOR;
        }
    }
    score = clamp(score, 0.0, 100.0);
    (score * 10.0).round() / 10.0
}

/// Map a score to a triage tier.
pub fn tier_for(score: f64) -> &'static str {
    if score >= TIER_CRITICAL {
        "CRITICAL"
    } else if score >= TIER_HIGH {
        "HIGH"
    } else if score >= TIER_MED {
        "MED"
    } else {
        "LOW"
    }
}

/// A scored CVE result.
#[derive(Debug, Clone, PartialEq)]
pub struct Scored {
    pub id: String,
    pub score: f64,
    pub tier: &'static str,
}

/// Score one CVE.
pub fn score_cve(id: &str, cvss: Option<f64>, epss: Option<f64>, kev: bool) -> Scored {
    let score = compute_score(cvss, epss, kev);
    Scored {
        id: id.to_string(),
        score,
        tier: tier_for(score),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kev_floor_enforced() {
        let s = score_cve("CVE-X", Some(1.0), Some(0.01), true);
        assert!(s.score >= KEV_FLOOR);
        assert!(s.tier == "HIGH" || s.tier == "CRITICAL");
    }

    #[test]
    fn critical_high_signals() {
        let s = score_cve("CVE-Y", Some(9.8), Some(0.94), true);
        assert_eq!(s.tier, "CRITICAL");
    }

    #[test]
    fn low_signals() {
        let s = score_cve("CVE-Z", Some(2.0), Some(0.01), false);
        assert_eq!(s.tier, "LOW");
    }

    #[test]
    fn missing_signals_no_escalation() {
        assert_eq!(compute_score(None, None, false), 0.0);
    }

    #[test]
    fn clamp_upper_bound() {
        assert!(compute_score(Some(100.0), Some(5.0), true) <= 100.0);
    }

    #[test]
    fn tier_boundaries() {
        assert_eq!(tier_for(90.0), "CRITICAL");
        assert_eq!(tier_for(89.9), "HIGH");
        assert_eq!(tier_for(70.0), "HIGH");
        assert_eq!(tier_for(69.9), "MED");
        assert_eq!(tier_for(40.0), "MED");
        assert_eq!(tier_for(39.9), "LOW");
    }

    #[test]
    fn kev_escalates_above_non_kev() {
        let a = compute_score(Some(5.0), Some(0.2), false);
        let b = compute_score(Some(5.0), Some(0.2), true);
        assert!(b > a);
    }

    #[test]
    fn rounding_one_decimal() {
        let s = compute_score(Some(7.5), Some(0.42), false);
        // 0.6*0.75 + 0.4*0.42 = 0.45 + 0.168 = 0.618 -> 61.8
        assert_eq!(s, 61.8);
    }
}
