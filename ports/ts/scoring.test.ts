import test from "node:test";
import assert from "node:assert/strict";
import { computeScore, tierFor, scoreCVE, KEV_FLOOR } from "./scoring.ts";

test("KEV floor enforced", () => {
  const s = scoreCVE({ id: "CVE-X", cvss: 1.0, epss: 0.01, kev: true });
  assert.ok(s.score >= KEV_FLOOR);
  assert.ok(s.tier === "HIGH" || s.tier === "CRITICAL");
});

test("critical high signals", () => {
  const s = scoreCVE({ id: "CVE-Y", cvss: 9.8, epss: 0.94, kev: true });
  assert.equal(s.tier, "CRITICAL");
});

test("low signals", () => {
  const s = scoreCVE({ id: "CVE-Z", cvss: 2.0, epss: 0.01, kev: false });
  assert.equal(s.tier, "LOW");
});

test("missing signals no escalation", () => {
  assert.equal(computeScore(null, null, false), 0.0);
  assert.equal(computeScore(undefined, undefined, false), 0.0);
});

test("clamp upper bound", () => {
  assert.ok(computeScore(100.0, 5.0, true) <= 100.0);
});

test("tier boundaries", () => {
  assert.equal(tierFor(90.0), "CRITICAL");
  assert.equal(tierFor(89.9), "HIGH");
  assert.equal(tierFor(70.0), "HIGH");
  assert.equal(tierFor(69.9), "MED");
  assert.equal(tierFor(40.0), "MED");
  assert.equal(tierFor(39.9), "LOW");
});

test("kev escalates above non-kev", () => {
  const a = computeScore(5.0, 0.2, false);
  const b = computeScore(5.0, 0.2, true);
  assert.ok(b > a);
});

test("rounding one decimal", () => {
  // 0.6*0.75 + 0.4*0.42 = 0.618 -> 61.8
  assert.equal(computeScore(7.5, 0.42, false), 61.8);
});
