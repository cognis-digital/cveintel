# Demo 07 — Monthly KEV-driven patch review

**Situation.** Once a month your security lead reconciles the org-wide vulnerability backlog
against the CISA **BOD 22-01** mandate (federal agencies *must* remediate KEV-listed CVEs by
the catalog due date; many private orgs adopt the same discipline). You have a 12-CVE
backlog and need two artifacts: (1) the KEV must-patch shortlist, and (2) the full ranked
list to plan the rest of the month.

**Where the data came from.** A representative enterprise backlog mixing four KEV-listed
heavyweights (Struts, Log4Shell, ProxyShell, Citrix Bleed) with eight quieter library/SSH
CVEs. CVSS values are published NVD base scores; KEV membership is marked for the four that
are genuinely on CISA's catalog. EPSS values are an illustrative snapshot.

**Run it.**

```bash
cveintel kev  scan.json --fixtures . --no-reasons        # the BOD 22-01 shortlist
cveintel rank scan.json --fixtures . --json > backlog.json   # full plan for tooling
```

**What to expect.**

- `kev` returns exactly the **four** KEV-listed CVEs, already ranked — that's your
  due-date-bound worklist.
- `rank` shows the other eight falling into **MED**, including a CVSS 9.8 OpenSSL bug that
  the composite model correctly parks below the KEV set.

**How to act.** Commit the four KEV items to the current sprint with hard due dates; load the
ranked `backlog.json` into your ticketing system so the MED items burn down in priority order
during normal maintenance. Diff this month's `kev` output against last month's to see what
newly entered the catalog.
