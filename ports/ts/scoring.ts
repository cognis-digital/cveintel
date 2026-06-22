/**
 * Core cveintel priority-scoring model, ported to TypeScript.
 *
 * Faithful port of cveintel/scoring.py: blends CVSS base severity, EPSS
 * exploitation probability, and CISA KEV presence into a 0-100 priority score
 * plus a triage tier. No dependencies, no network, no exploit logic.
 * Defensive / authorized-use only.
 */

export const W_CVSS = 0.6;
export const W_EPSS = 0.4;
export const KEV_BONUS = 0.5;
export const KEV_FLOOR = 70.0;

export const TIER_CRITICAL = 90.0;
export const TIER_HIGH = 70.0;
export const TIER_MED = 40.0;

export type Tier = "CRITICAL" | "HIGH" | "MED" | "LOW";

export interface CVE {
  id: string;
  cvss?: number | null;
  epss?: number | null;
  kev?: boolean;
}

export interface Scored {
  id: string;
  score: number;
  tier: Tier;
}

function clamp(v: number, lo: number, hi: number): number {
  if (v < lo) return lo;
  if (v > hi) return hi;
  return v;
}

function round1(v: number): number {
  return Math.round(v * 10) / 10;
}

/** Composite priority score (0-100), one decimal. */
export function computeScore(
  cvss: number | null | undefined,
  epss: number | null | undefined,
  kev: boolean,
): number {
  const cvssN = clamp((cvss ?? 0) / 10.0, 0, 1);
  const epssN = clamp(epss ?? 0, 0, 1);

  const base = 100.0 * (W_CVSS * cvssN + W_EPSS * epssN);

  let score = base;
  if (kev) {
    score = base + KEV_BONUS * (100.0 - base);
    if (score < KEV_FLOOR) score = KEV_FLOOR;
  }
  return round1(clamp(score, 0, 100));
}

/** Map a score to a triage tier. */
export function tierFor(score: number): Tier {
  if (score >= TIER_CRITICAL) return "CRITICAL";
  if (score >= TIER_HIGH) return "HIGH";
  if (score >= TIER_MED) return "MED";
  return "LOW";
}

/** Score one CVE. */
export function scoreCVE(c: CVE): Scored {
  const score = computeScore(c.cvss, c.epss, !!c.kev);
  return { id: c.id, score, tier: tierFor(score) };
}
