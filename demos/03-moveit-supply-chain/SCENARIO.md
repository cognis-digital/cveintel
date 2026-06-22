# Demo 03 — MOVEit managed-file-transfer supply-chain advisory

**Situation.** A vendor advisory drops on your managed-file-transfer (MOVEit Transfer)
deployment — the same product class the Cl0p group mass-exploited to breach thousands of
organizations. The advisory bundles three SQL-injection CVEs released over a couple of weeks.
Your asset inventory already knows the CVSS for each (it came pre-populated from the vendor
bulletin), but you want `cveintel` to layer KEV + EPSS on top and tell you the patch order.

**Where the data came from.** The three MOVEit Transfer SQLi CVEs from the May–June 2023
advisories. `scan.json` is in the **records** input format with CVSS already on each record
(authoritative — `cveintel` will not overwrite it) and `kev:true` hand-set on the original
zero-day. The `kev.json` fixture is in CISA-catalog shape and the `epss.json` fixture is in
the EPSS-API shape, demonstrating both real-world feed layouts. EPSS values are illustrative.

**Run it.**

```bash
cveintel enrich scan.json --fixtures . --json   # see the gap-fill happen
cveintel rank   scan.json --fixtures . --no-reasons
```

**What to expect.**

- `enrich` keeps your input CVSS untouched, fills `epss` from the API-shaped fixture, and
  **promotes** `CVE-2023-35708` to `kev:true` from the catalog while correctly leaving
  `CVE-2023-35036` at `kev:false` (it was never KEV-listed).
- `rank` puts the two KEV SQLi-to-RCE bugs in **CRITICAL** and the non-KEV follow-up in
  **HIGH** — still urgent (9.1 CVSS) but a notch below the proven-exploited pair.

**How to act.** Patch to the fixed MOVEit Transfer build immediately and hunt for the
LEMURLOOT webshell / anomalous file-transfer activity — for this product, patching does not
undo data already exfiltrated, so treat a vulnerable internet-facing instance as a possible
breach, not just a missing patch.
