# Demo 01 — Log4Shell incident triage

**Situation.** It's the morning after a dependency scanner (e.g. `grype`, `trivy`, or a
Dependabot sweep) flagged the Log4j family across your Java fleet. You have four CVEs on
the board and a queue of teams asking "which do we hotfix tonight, and which can wait for
the regular patch window?" Raw CVSS alone is misleading here: two of these four are merely
high-CVSS-on-paper, while the real fire is the pair that attackers are spraying the internet
with.

**Where the data came from.** The four Log4j 2.x CVEs disclosed Dec 2021. CVSS base scores
are the published NVD values; KEV membership reflects the two entries CISA added to the
Known Exploited Vulnerabilities catalog. EPSS values are an illustrative snapshot in the
shape FIRST.org publishes.

**Run it.**

```bash
cveintel rank scan.json --fixtures .
```

**What to expect.**

- `CVE-2021-44228` (Log4Shell itself) and `CVE-2021-45046` land in **CRITICAL** — both are
  KEV-listed, so the KEV escalator pulls them above 90 even though one has a sub-10 CVSS.
- `CVE-2021-45105` (a recursion **DoS**) and `CVE-2021-44832` (RCE only when the attacker
  already controls the logging config) stay in **MED**. They are genuinely lower urgency:
  no in-the-wild exploitation, lower EPSS.

**How to act.** Emergency-patch the two CRITICAL/KEV entries tonight (upgrade to a fixed
Log4j 2.x, or apply the `formatMsgNoLookups` mitigation as a stopgap). Schedule the two MED
items into the next normal maintenance window. Re-run with `--fail-on critical` in your
deploy pipeline so a build that still ships Log4Shell can't go out.
