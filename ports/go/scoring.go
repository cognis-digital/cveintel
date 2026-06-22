// Package cveintel implements the core cveintel priority-scoring model in Go.
//
// This is a faithful port of cveintel/scoring.py: it blends CVSS base
// severity, EPSS exploitation probability, and CISA KEV presence into a single
// 0-100 priority score and a triage tier. Pure standard library.
//
// Defensive / authorized-use only. No network, no exploit logic.
package cveintel

import "math"

// Signal weights (sum to 1.0 so base stays in [0,100]).
const (
	WCVSS    = 0.6
	WEPSS    = 0.4
	KevBonus = 0.5  // fraction of the gap to 100 closed when KEV-listed
	KevFloor = 70.0 // minimum score for any KEV-listed CVE

	TierCritical = 90.0
	TierHigh     = 70.0
	TierMed      = 40.0
)

// CVE holds the input signals for one vulnerability.
// CVSS and EPSS use pointers so "absent" is distinct from 0.
type CVE struct {
	ID   string
	CVSS *float64
	EPSS *float64
	KEV  bool
}

// Scored is the computed result.
type Scored struct {
	ID    string
	Score float64
	Tier  string
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func deref(p *float64) float64 {
	if p == nil {
		return 0.0
	}
	return *p
}

// ComputeScore returns the composite priority score (0-100).
func ComputeScore(cvss, epss *float64, kev bool) float64 {
	cvssN := clamp(deref(cvss)/10.0, 0.0, 1.0)
	epssN := clamp(deref(epss), 0.0, 1.0)

	base := 100.0 * (WCVSS*cvssN + WEPSS*epssN)

	score := base
	if kev {
		score = base + KevBonus*(100.0-base)
		if score < KevFloor {
			score = KevFloor
		}
	}
	score = clamp(score, 0.0, 100.0)
	return math.Round(score*10.0) / 10.0
}

// TierFor maps a score to a triage tier.
func TierFor(score float64) string {
	switch {
	case score >= TierCritical:
		return "CRITICAL"
	case score >= TierHigh:
		return "HIGH"
	case score >= TierMed:
		return "MED"
	default:
		return "LOW"
	}
}

// ScoreCVE computes score + tier for one CVE.
func ScoreCVE(c CVE) Scored {
	s := ComputeScore(c.CVSS, c.EPSS, c.KEV)
	return Scored{ID: c.ID, Score: s, Tier: TierFor(s)}
}
