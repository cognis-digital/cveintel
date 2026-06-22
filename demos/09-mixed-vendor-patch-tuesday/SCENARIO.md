# Demo 09 — Mixed-vendor patch cycle (Patch Tuesday week)

**Situation.** It's a heavy patch week: Microsoft's monthly bundle dropped at the same time
as out-of-band Fortinet and ConnectWise advisories. Your team can't drop everything for all
five, and the vendors' own severity labels don't agree on a cross-product order. You need one
ranked sheet that merges Microsoft, Fortinet, and ConnectWise findings into a single
defensible patch sequence.

**Where the data came from.** Five real February-2024-era CVEs across three vendors: two
Windows SmartScreen bypasses, the Outlook "MonikerLink" RCE, the FortiOS SSL-VPN
out-of-bounds-write RCE, and the ConnectWise ScreenConnect auth bypass. CVSS values are the
published NVD base scores; KEV membership is marked for the three genuinely on CISA's catalog
(ScreenConnect, FortiOS, the exploited SmartScreen bug). EPSS values are an illustrative
snapshot.

**Run it.**

```bash
cveintel rank scan.json --fixtures .
```

**What to expect.** A clean cross-vendor order:

- **CRITICAL** — ScreenConnect (10.0 + KEV) and FortiOS SSL-VPN RCE (9.6 + KEV): remote,
  unauthenticated, actively exploited internet-facing boxes.
- **HIGH** — the KEV-listed SmartScreen bypass (real campaigns) and the CVSS-9.8 Outlook
  MonikerLink RCE (high severity, not yet KEV).
- **MED** — the second SmartScreen bypass, which is neither exploited nor high-EPSS.

**How to act.** Patch the two CRITICAL internet-facing appliances first (and rotate
ScreenConnect admin credentials). Push the SmartScreen and Outlook client-side fixes through
your normal endpoint-management ring next; let the quiet second SmartScreen bypass ride the
standard monthly rollout.
