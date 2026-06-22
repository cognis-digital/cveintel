package cveintel

import "testing"

func f(v float64) *float64 { return &v }

func TestKevFloor(t *testing.T) {
	// Weak signals but KEV-listed -> at least the floor (HIGH tier).
	s := ScoreCVE(CVE{ID: "CVE-X", CVSS: f(1.0), EPSS: f(0.01), KEV: true})
	if s.Score < KevFloor {
		t.Fatalf("KEV score %.1f below floor %.1f", s.Score, KevFloor)
	}
	if s.Tier != "HIGH" && s.Tier != "CRITICAL" {
		t.Fatalf("KEV tier should be HIGH/CRITICAL, got %s", s.Tier)
	}
}

func TestCriticalHighSignals(t *testing.T) {
	s := ScoreCVE(CVE{ID: "CVE-Y", CVSS: f(9.8), EPSS: f(0.94), KEV: true})
	if s.Tier != "CRITICAL" {
		t.Fatalf("expected CRITICAL, got %s (%.1f)", s.Tier, s.Score)
	}
}

func TestLowSignals(t *testing.T) {
	s := ScoreCVE(CVE{ID: "CVE-Z", CVSS: f(2.0), EPSS: f(0.01), KEV: false})
	if s.Tier != "LOW" {
		t.Fatalf("expected LOW, got %s (%.1f)", s.Tier, s.Score)
	}
}

func TestMissingSignalsNoEscalation(t *testing.T) {
	s := ComputeScore(nil, nil, false)
	if s != 0.0 {
		t.Fatalf("expected 0 with no signals, got %.1f", s)
	}
}

func TestClampUpperBound(t *testing.T) {
	s := ComputeScore(f(100.0), f(5.0), true)
	if s > 100.0 {
		t.Fatalf("score exceeded 100: %.1f", s)
	}
}

func TestTierBoundaries(t *testing.T) {
	cases := []struct {
		score float64
		tier  string
	}{
		{90.0, "CRITICAL"},
		{89.9, "HIGH"},
		{70.0, "HIGH"},
		{69.9, "MED"},
		{40.0, "MED"},
		{39.9, "LOW"},
		{0.0, "LOW"},
	}
	for _, c := range cases {
		if got := TierFor(c.score); got != c.tier {
			t.Errorf("TierFor(%.1f) = %s; want %s", c.score, got, c.tier)
		}
	}
}

func TestKevEscalatesAboveNonKev(t *testing.T) {
	a := ComputeScore(f(5.0), f(0.2), false)
	b := ComputeScore(f(5.0), f(0.2), true)
	if b <= a {
		t.Fatalf("KEV (%.1f) should exceed non-KEV (%.1f)", b, a)
	}
}
