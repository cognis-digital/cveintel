# Demo 04 — Exchange ProxyShell / ProxyLogon exploit chains

**Situation.** You run on-prem Microsoft Exchange and your detection team handed you the two
infamous 2021 exploit chains as a single worklist: **ProxyLogon** (`CVE-2021-26855` +
`CVE-2021-27065`) and **ProxyShell** (`CVE-2021-34473` + `CVE-2021-34523` + `CVE-2021-31207`).
Both were used for mass webshell deployment. You need a single ranked sheet that proves to
leadership these are all top-of-queue.

**Where the data came from.** The five CVEs that make up the two chains. CVSS values are the
published NVD base scores; every one is on CISA's KEV catalog. This demo deliberately uses
the **`{"cves": [...]}` wrapper input shape** and a **bare-list `kev.json`** fixture to
exercise those alternate formats. EPSS values are an illustrative snapshot.

**Run it.**

```bash
cveintel rank scan.json --fixtures .
cveintel kev  scan.json --fixtures . --no-reasons   # confirm all five are KEV-listed
```

**What to expect.** Four of five land in **CRITICAL** and the fifth (`CVE-2021-31207`, a
post-auth arbitrary-write that's only useful *after* the bypass) lands at the top of
**HIGH** via the KEV floor. The `kev` subcommand returns all five — none can be dismissed as
"theoretical."

**How to act.** These chains are link-by-link: the auth-bypass + write primitive is what
turns into a webshell, so patch the whole set, not just the headline RCE. Because mass
exploitation predates most patch dates, **assume compromise** on any server that was
internet-exposed and unpatched — run the official Exchange IOC/webshell sweep before
calling it closed.
