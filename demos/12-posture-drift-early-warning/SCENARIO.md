# Demo 12 — Posture drift / early warning (`cveintel diff`)

**Situation.** You run a nightly external-attack-surface scan against your edge fleet:
Citrix NetScaler, Ivanti Connect Secure, a Palo Alto GlobalProtect portal, and (newly
deployed) a ConnectWise ScreenConnect instance. Your scanner already records CVSS, EPSS,
and KEV state per finding. Last night's snapshot looked tolerable — nothing was on CISA
KEV except the MOVEit box, which you'd already pulled offline. This morning's snapshot is
a different world. The question is not "what is my exposure?" — it's **"what changed, and
what now demands an emergency change ticket *today*?"**

`cveintel diff` answers exactly that. It diffs two scored snapshots and classifies every
change by *why it matters to a defender*.

**Where the data came from.** These are real, documented edge-appliance CVEs from the
2023–2024 wave of internet-facing-device mass-exploitation:

| CVE | Product | Note |
|-----|---------|------|
| CVE-2023-4966  | Citrix NetScaler ADC/Gateway | "Citrix Bleed" session-token disclosure |
| CVE-2023-46805 | Ivanti Connect Secure | auth bypass (chained with 21887) |
| CVE-2024-21887 | Ivanti Connect Secure | command injection |
| CVE-2023-34362 | Progress MOVEit Transfer | Cl0p mass-exploitation SQLi |
| CVE-2024-3400  | Palo Alto PAN-OS GlobalProtect | command injection |
| CVE-2024-1709  | ConnectWise ScreenConnect | trivial auth bypass |

CVSS base scores are the published NVD values. The EPSS and KEV states in `before.json`
vs `after.json` are an **illustrative** drift snapshot in the shape your scanner exports —
they model the well-documented pattern where these appliances sat at low EPSS / not-KEV
for a window, then spiked and were KEV-listed within days as exploitation went wide.

**Run it.**

```bash
cveintel diff before.json after.json --fixtures .
```

**What to expect.**

- **Four appliances flip from MED to CRITICAL/HIGH in one night.** Citrix Bleed, both
  Ivanti CVEs, and the PAN-OS bug all (a) got KEV-listed, (b) had EPSS spike 60–80
  percentage points, and (c) crossed a tier boundary. `cveintel diff` stacks all three
  drift kinds on one line (`KEV+,TIER^,EPSS^`) so you see the convergence at a glance.
- **A brand-new appliance (ScreenConnect, CVE-2024-1709) appears already on KEV** —
  `NEW,KEV+`. A newly-stood-up asset that's *born* known-exploited is the worst case;
  it lands at CRITICAL/99 immediately.
- **MOVEit (CVE-2023-34362) shows `GONE`** — it dropped out of scope. That confirms the
  decommission you did last week actually removed the exposure; it's the one piece of
  *good* news, and the tool says so explicitly rather than burying it.

**Gate it in CI / the nightly pipeline.**

```bash
cveintel diff before.json after.json --fixtures . --worsened-only --fail-on-drift
echo $?   # 2 == something got worse since the prior snapshot
```

`--fail-on-drift` exits non-zero the moment *any* CVE worsens (new KEV listing, tier
escalation, EPSS spike, upward CVSS revision, or a newly-appeared finding). Wire that into
the nightly job and it pages you the night a dormant edge CVE goes hot — typically *days*
before it would have surfaced in a manual KEV review.

**How to act.** Everything flagged `KEV+` tonight is an emergency change: patch or pull the
appliance offline now. The `EPSS^`-only items (probability rising but not yet KEV) are your
*early-warning* tier — get ahead of them before they become tonight's KEV additions.
Confirm `GONE` items really are decommissioned and close their tickets.

> Defensive / situational-awareness use only. `cveintel diff` reports what got worse so a
> defender can re-prioritize remediation. It contains no exploitation or targeting logic.
