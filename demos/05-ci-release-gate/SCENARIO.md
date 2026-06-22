# Demo 05 — CI/CD release gate (block-the-build)

**Situation.** Your build pipeline runs an SCA (software-composition analysis) scan on every
PR and exports the findings as JSON. You want the pipeline to **fail the build** when a
dependency carries a genuinely urgent vulnerability — but you do *not* want to block on every
high-CVSS finding, because that trains engineers to rubber-stamp overrides. `cveintel`'s
`--fail-on` gate keys off the composite (KEV + EPSS + CVSS) tier, so only real urgency stops
the line.

**Where the data came from.** A small dependency set: the Apache Struts 2 RCE
(`CVE-2017-5638`, the Equifax-breach root cause, CVSS 10.0, KEV-listed) plus three real but
quiet JS-ecosystem CVEs (lodash / loader-utils) that scanners flag constantly. CVSS values
are the published NVD base scores; only the Struts bug is on CISA's KEV. EPSS values are an
illustrative snapshot.

**Run it.**

```bash
cveintel rank scan.json --fixtures . --no-reasons --fail-on high
echo "exit code: $?"   # 2 -> build blocked
```

**What to expect.** Exit code **2** and a `FAIL:` line on stderr. The Struts RCE is
**CRITICAL** (KEV escalator). The three JS deps — including a CVSS 9.8 prototype-pollution —
stay in **MED** because nobody is exploiting them, so on their own they would *not* trip the
gate. Try the same scan with `loader-utils`/`lodash` only and the build passes.

**How to act.** Wire this exact command into your pipeline:

```yaml
- run: cveintel rank sca-report.json --fixtures kev-feed/ --fail-on high
```

A non-zero exit halts the merge until the Struts dependency is bumped. The quiet
prototype-pollution findings flow to the normal backlog instead of crying wolf on every PR.
