# Demo 02 — Internet-facing edge appliance exposure

**Situation.** Your external attack-surface management tool fingerprinted the VPN/gateway
appliances on your perimeter and matched them to known CVEs. These are exactly the boxes
ransomware affiliates and state actors hammer first, because one bug on an edge device =
a foothold inside. You need to know the order to pull devices offline / emergency-patch.

**Where the data came from.** Four heavily-documented perimeter CVEs: Citrix Bleed
(`CVE-2023-4966`), the Ivanti Connect Secure chain (`CVE-2024-21887` + `CVE-2023-46805`),
and the long-lived Fortinet FortiOS SSL-VPN path traversal (`CVE-2018-13379`). CVSS values
are the published NVD base scores; all four are on CISA's KEV catalog. EPSS values are an
illustrative high-exploitation snapshot consistent with their real-world activity.

**Run it.**

```bash
cveintel rank scan.json --fixtures . --no-reasons
cveintel rank scan.json --fixtures . --json   # for ticketing automation
```

**What to expect.** All four land in **CRITICAL** — which is the correct answer for
KEV-listed, internet-reachable RCE/credential-theft bugs. When everything is critical, the
*ordering* is the deliverable: `cveintel` breaks the tie by composite score (CVSS + EPSS),
so the oldest-but-most-sprayed Fortinet flaw and Citrix Bleed sort to the very top.

**How to act.** This is a same-day event, not a patch-window item. Patch or pull each
appliance now; for Citrix Bleed and the Ivanti chain, **rotate sessions/credentials** after
patching because the bugs leak tokens — patching alone doesn't evict an attacker who already
grabbed a session. Feed the `--json` output straight into your incident ticket queue.
