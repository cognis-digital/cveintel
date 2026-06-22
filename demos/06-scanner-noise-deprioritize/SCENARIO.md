# Demo 06 — Cutting through scanner noise (don't chase every 9.8)

**Situation.** Your vulnerability scanner just dumped a wall of "Critical 9.8 / High 7.5"
OpenSSL findings and one Log4Shell hit. By raw CVSS, the OpenSSL bugs look like a four-alarm
fire. But CVSS measures *how bad if exploited* — not *whether anyone is exploiting it*. This
demo shows `cveintel` doing its core job: refusing to let a high-CVSS-but-quiet bug
out-rank the one finding that is actually on fire.

**Where the data came from.** Three real, high-CVSS OpenSSL CVEs that never saw broad
in-the-wild exploitation (`CVE-2021-3711` SM2 overflow 9.8, `CVE-2022-0778` BN_mod_sqrt DoS,
`CVE-2023-0286` type confusion), plus Log4Shell (`CVE-2021-44228`) as the genuine emergency.
CVSS values are the published NVD base scores; only Log4Shell is KEV-listed. EPSS values are
an illustrative snapshot reflecting their low real-world exploitation.

**Run it.**

```bash
cveintel rank scan.json --fixtures . --no-reasons
```

**What to expect.** Log4Shell sits alone in **CRITICAL** at the top. The **CVSS 9.8**
OpenSSL SM2 bug ranks *below* it and lands in **MED** — because its EPSS is ~4% and it isn't
KEV-listed. The two 7.x OpenSSL items follow, also MED. The composite model has effectively
told you: "patch the Log4j box tonight; the OpenSSL items are real but go in the normal
queue."

**How to act.** Trust the tiering to triage your week: emergency-patch the CRITICAL, batch
the MED OpenSSL upgrades into your next library-refresh cycle. Re-run weekly with `--live`
and the MED items will auto-escalate the moment EPSS spikes or CISA adds one to KEV.
