# Demo 10 — Asset-aware triage and the exposure tie-break

**Situation.** Your CMDB joins each vulnerability finding to the asset it lives on, including
network exposure (`internet` vs `internal`). `cveintel` scores the *vulnerability*; you bring
the *exposure context*. This demo shows how the two combine: the tool ranks by exploitation
urgency and **carries your asset/exposure fields straight through** so you can apply the last
mile of judgment.

**Where the data came from.** Four real, KEV-or-quiet CVEs deliberately attached to assets
with different exposure: ScreenConnect on an internet-facing portal, Citrix Bleed on the
perimeter VPN, Log4Shell on an *internal-only* microservice, and an OpenSSL DoS on an
internal CI runner. The extra `asset` / `exposure` keys are custom fields — `cveintel`
preserves any unknown keys on a record. CVSS values are published NVD base scores; KEV
membership is real; EPSS values are an illustrative snapshot.

**Run it.**

```bash
cveintel rank   scan.json --fixtures . --no-reasons
cveintel enrich scan.json --fixtures . --json   # note asset/exposure survive enrichment
```

**What to expect.** Three KEV CVEs tie at the top of **CRITICAL**; the internal OpenSSL DoS
drops to **MED**. The `enrich --json` output still carries `asset` and `exposure` on every
record, so you can post-filter.

**How to act.** Layer exposure on top of the tier. Among the three CRITICALs, the two
**internet-facing** ones (ScreenConnect portal, Citrix VPN) are your same-hour actions; the
**internal-only** Log4Shell — though identically scored — has no inbound path, so it's a
fast-follow rather than an outage-grade emergency. Filter the JSON to act:

```bash
cveintel enrich scan.json --fixtures . --json \
  | jq '[.[] | select(.kev and .exposure=="internet")] | sort_by(-.cvss)'
```

The lesson: `cveintel` tells you *what attackers can exploit*; your exposure data tells you
*what they can reach* — use both.
