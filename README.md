# cveintel

**CVE enrichment + prioritization CLI** — correlate base severity (CVSS), known-exploited status (CISA KEV), and exploitation probability (EPSS) into a single explained "patch these first, here's why" ranking. Works fully offline on fixture JSON; optionally fetches live data.


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ cveintel --version
cveintel 0.1.0
```

```console
$ cveintel --help
usage: cveintel [-h] [--version] {rank,enrich,kev,diff,feeds,sbom,active} ...

Correlate CVSS, CISA KEV, and EPSS into an explained CVE priority ranking.
Offline by default.

positional arguments:
  {rank,enrich,kev,diff,feeds,sbom,active}
    rank                ranked, explained priority list
    enrich              merge KEV/EPSS/CVSS onto records
    kev                 filter to KEV-listed CVEs only
    diff                posture drift between two scan snapshots
                        (KEV/tier/EPSS/CVSS)
    feeds               manage the edge/air-gap data-feed cache (cisa-
                        kev/epss/nvd-cve)
    sbom                PASSIVE: match an SBOM/package list to CVEs (offline
                        corpus, no network)
    active              ACTIVE (AUTHORIZED USE ONLY): read-only banner/header
                        probe of consented, in-scope targets; OFF by default

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```

> Blocks above are real `cveintel` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
"rank": [
  {
    "cve_id": "CVE-2022-1234",
    "priority": "High",
    "reason": "CVSS score: 9.8, EPSS rating: Critical"
  },
  {
    "cve_id": "CVE-2023-5678",
    "priority": "Medium",
    "reason": "CVSS score: 5.5, KEV tier: Yellow"
  }
]
}
```

<!-- cognis:example:end -->

## Why

CVSS alone over-ranks vulnerabilities that nobody is actually exploiting. `cveintel` fuses three independent signals so your triage reflects *real-world* urgency:

- **CVSS** — base technical severity (how bad if exploited)
- **CISA KEV** — is it on the Known Exploited Vulnerabilities catalog (proven in-the-wild exploitation)
- **EPSS** — FIRST.org's 30-day exploitation-probability score

KEV presence acts as a strong escalator: a "medium" CVSS bug that attackers are actively using should jump the queue, and `cveintel` makes it do exactly that — with a plain-language explanation for every ranking.

## Install

```bash
pip install cognis-cveintel
```

Or from source:

```bash
git clone https://github.com/cognis-digital/cveintel
cd cveintel
pip install -e ".[dev]"
```

Python 3.10+. Standard library only — no third-party runtime dependencies.

## Usage

### Rank (the headline command)

```bash
cveintel rank examples/cves.json
```

```
CVE                TIER       SCORE  CVSS   EPSS  KEV
--------------------------------------------------------
CVE-2024-10001     CRITICAL   98.2   9.8   0.94  yes
    - in CISA KEV - actively exploited in the wild
    - EPSS 0.94 - high exploitation likelihood (94%)
    - CVSS 9.8 - critical base severity
CVE-2024-10004     HIGH       83.0   9.1   0.71    -
    - EPSS 0.71 - high exploitation likelihood (71%)
    - CVSS 9.1 - critical base severity
CVE-2024-10003     HIGH       80.9   7.5   0.42  yes
    - in CISA KEV - actively exploited in the wild
    - EPSS 0.42 - moderate exploitation likelihood (42%)
    - CVSS 7.5 - high base severity
CVE-2024-10002     LOW        39.8   6.1   0.08    -
    - EPSS 0.08 - low exploitation likelihood (8%)
    - CVSS 6.1 - medium base severity
CVE-2024-10005     LOW        33.0   5.3   0.03    -
    ...
CVE-2024-10006     LOW        26.2   4.3   0.01    -
    ...
```

JSON for pipelines:

```bash
cveintel rank examples/cves.json --json
```

SARIF 2.1.0 for code-scanning dashboards (GitHub code-scanning, Azure DevOps, etc.):

```bash
cveintel rank examples/cves.json --sarif > cveintel.sarif
```

Each CVE becomes one SARIF `result` (CVE id as `ruleId`, NVD detail page as
`helpUri`); the composite tier maps to the SARIF `level` (CRITICAL/HIGH →
`error`, MED → `warning`, LOW → `note`) and the 0-100 composite score is carried
as the SARIF `rank`, so an exploitation-aware ranking flows straight into any
SARIF-aware viewer.

### Enrich

Merge KEV/EPSS/CVSS signals onto bare CVE ids (or partial records):

```bash
cveintel enrich examples/cves.json --json
```

### KEV filter

Show only CVEs on the CISA KEV catalog:

```bash
cveintel kev examples/cves.json
```

### Diff (posture drift / early warning)

Compare two scan snapshots and surface only what **changed** — newly
known-exploited CVEs (`KEV+`), tier escalations (`TIER^`), EPSS spikes
(`EPSS^`), upward CVSS revisions (`CVSS^`), newly-appeared findings (`NEW`), and
remediated/decommissioned ones (`GONE`). Unchanged CVEs are omitted; output is
sorted most-urgent first. Deterministic and fully offline.

```bash
cveintel diff yesterday.json today.json
```

```
CVE                CHANGE                          WAS         NOW
----------------------------------------------------------------------
CVE-2024-3400      KEV+,TIER^,EPSS^             MED/65  CRITICAL/99 !
    - newly listed on CISA KEV - proven in-the-wild exploitation
    - tier escalated MED -> CRITICAL
    - EPSS spiked 0.12 -> 0.93 (+81 pts) - rising exploitation likelihood
...
6 changed (5 worsened): KEV+5 TIER^4 EPSS^4 NEW1 GONE1
```

`--worsened-only` keeps just the changes that make the posture worse, and
`--fail-on-drift` exits non-zero (`2`) the moment any CVE worsens — wire it into
a nightly job to get paged the night a dormant edge CVE goes hot, often *days*
before it would surface in a manual KEV review:

```bash
cveintel diff yesterday.json today.json --worsened-only --fail-on-drift
cveintel diff yesterday.json today.json --json          # {summary, drift} for dashboards
cveintel diff yesterday.json today.json --feeds --offline   # air-gapped drift analysis
```

EPSS movement is often the **earliest** machine-readable signal that a
vulnerability is being weaponized — `diff` is built to catch your attack surface
moving through `EPSS rises → KEV-listed → mass exploitation` and page you on the
transition rather than the steady state. Full write-up:
[`docs/posture-drift.md`](docs/posture-drift.md).

### CI / compliance gate

Exit non-zero (code `2`) if anything meets a tier — drop this in a pipeline to block a release on actively-exploited or critical findings:

```bash
cveintel rank scan.json --fail-on critical   # fail if any CRITICAL
cveintel rank scan.json --fail-on high        # fail if any HIGH or CRITICAL
```

### Live data (optional)

By default everything runs offline against local fixtures. Add `--live` to pull current signals from NVD, the CISA KEV feed, and the EPSS API:

```bash
cveintel rank scan.json --live --live-timeout 30
```

The network layer is isolated in `cveintel/live.py` and is never used in the offline path or the test suite.

## Passive vs Active

cveintel has two operating modes. **Passive is the default and is what you
almost always want.**

| | Passive (default) | Active (authorization-gated) |
| --- | --- | --- |
| Network | None — reads only what you give it + the bundled offline corpus | Read-only HTTP(S) to *consented, in-scope* hosts |
| What it does | Enrich/rank CVEs, scan an SBOM against ~262k known vulns | Read response headers, map disclosed banners to CVEs |
| Enabled by | always on | `--authorized` **and** `--target-allowlist` **and** `--rate-limit` |
| Sends exploits? | n/a | **No.** Never. Read-only banner check only. |

### Passive: SBOM scan (offline corpus)

cveintel bundles `cveintel/cognis_vulndb.jsonl.gz` — a ~262k-record offline
vulnerability corpus (OSV across PyPI/npm/Go/Maven/RubyGems/crates.io/NuGet).
The `sbom` subcommand matches a software bill of materials against it with **no
network**, computing CVSS base scores directly from the CVSS vector strings in
the corpus so findings are ranked, not just listed:

```bash
cveintel sbom examples/sbom.json                 # CycloneDX, SPDX-ish, or a plain name list
cveintel sbom requirements.txt --json
cveintel sbom sbom.json --sarif > findings.sarif
cveintel sbom sbom.json --fail-on high           # CI gate on the offline corpus
```

Accepts a JSON list of package names, a list of `{name, ecosystem}` objects,
CycloneDX (`components`/`purl`), an SPDX-ish `packages` list, or a
newline-delimited text file. Findings de-duplicate on CVE id (highest severity
wins) and flow through the same scoring/SARIF/`--fail-on` machinery as `rank`.

You can also fold the bundled corpus into ordinary enrichment to **fill missing
CVSS** offline (non-destructive — never overrides authoritative input):

```bash
cveintel rank scan.json --vulndb        # backfill CVSS from the offline corpus
```

### Active mode — AUTHORIZED USE ONLY

> **WARNING.** Active mode contacts a remote host over the network. Run it
> **only** against systems you own or have **explicit written permission** to
> test. Unauthorized scanning may be illegal. cveintel deliberately performs
> only the most benign interaction possible — a single read-only HTTP(S) request
> to read response headers (`Server:`, `X-Powered-By:`) and map any disclosed
> product/version banners to known CVEs. It sends **no** exploit payloads, **no**
> auth attacks, **no** fuzzing, and **no** port sweeps.

Active mode is **off by default** and refuses to run unless **all** of the
following are supplied:

1. `--authorized` — you affirm you have written authorization.
2. `--target-allowlist HOST` (repeatable; supports `*.example.com`) — the scope.
   Any target whose host is not in the allowlist is **refused, never probed**.
3. `--rate-limit` > 0 — requests/second; a minimum inter-request delay is enforced.

```bash
# Probe a consented host you own; banners map to corpus CVEs.
cveintel active https://staging.example.com/ \
    --authorized \
    --target-allowlist '*.example.com' \
    --rate-limit 2 \
    --json
```

A loud authorized-use banner is always printed to stderr. Out-of-scope targets
in a multi-target run are skipped (and recorded) rather than probed. The active
code path is isolated in `cveintel/active.py`; its tests run only against
`localhost` / a fixture HTTP server / mocks — never a real external host.

## Language ports

The core scoring model (CVSS + EPSS + CISA KEV → 0-100 score + tier) is ported
to three other languages under [`ports/`](ports/), each with its own tests and a
CI workflow ([`.github/workflows/ports.yml`](.github/workflows/ports.yml)) that
builds and tests them on GitHub runners:

| Language | Path | Run tests |
| --- | --- | --- |
| Go | [`ports/go`](ports/go) | `cd ports/go && go test ./...` |
| Rust | [`ports/rust`](ports/rust) | `cd ports/rust && cargo test` |
| TypeScript | [`ports/ts`](ports/ts) | `cd ports/ts && node --test --experimental-strip-types` |

All ports reproduce the same KEV floor (70), KEV escalation, weights
(`W_CVSS=0.6`, `W_EPSS=0.4`), and tier thresholds as the Python reference, so a
finding scores identically in any of them.

## Data feeds (edge / air-gap deployable)

For disconnected, edge, or air-gapped operation, cveintel ships a small,
standard-library **data-feed cache** (`cveintel/datafeeds.py` +
`cveintel/data_feeds_2026.json`) that fetches the three real, authoritative,
**keyless** public sources it consumes over HTTPS, caches each to disk, and
re-serves them **offline** so triage keeps working with zero network egress.

The catalog is filtered to exactly the feeds cveintel uses:

| Feed id | Source | URL |
| ------- | ------ | --- |
| `cisa-kev` | CISA Known Exploited Vulnerabilities | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| `epss` | FIRST EPSS exploit-probability scores | `https://api.first.org/data/v1/epss` |
| `nvd-cve` | NIST NVD CVE API 2.0 (CVSS base) | `https://services.nvd.nist.gov/rest/json/cves/2.0` |

### The `feeds` subcommand

```bash
cveintel feeds list                        # the 3 feeds + cache freshness
cveintel feeds update                      # fetch + cache all three (network)
cveintel feeds update epss                 # refresh just one
cveintel feeds get cisa-kev --offline      # print a cached feed, no network
cveintel feeds snapshot-export feeds.tar.gz   # tar the cache for sneakernet
cveintel feeds snapshot-import feeds.tar.gz   # rehydrate in an enclave
```

The cache location is `COGNIS_FEEDS_CACHE` (default `~/.cache/cognis-feeds`).

### Enriching from the cache (offline)

`rank` / `enrich` / `kev` can source signals from the feed cache instead of
fixtures or the legacy `--live` path:

```bash
# refresh from network, then enrich:
cveintel rank scan.json --feeds

# air-gapped: serve every signal from the local cache, no network at all:
cveintel rank scan.json --feeds --offline
```

### Air-gap (sneakernet) workflow

```bash
# On a CONNECTED host:
cveintel feeds update
cveintel feeds snapshot-export feeds.tar.gz      # copy this onto a USB drive

# On the AIR-GAPPED host:
export COGNIS_FEEDS_CACHE=/srv/cveintel/feed-cache
cveintel feeds snapshot-import feeds.tar.gz
cveintel rank scan.json --feeds --offline        # full triage, zero egress
```

See [`demos/11-airgap-feeds-enrichment`](demos/11-airgap-feeds-enrichment/) for
an end-to-end offline walkthrough backed by a committed trimmed feed cache.

## Input formats

`<cves.json>` may be any of:

```json
["CVE-2024-10001", "CVE-2024-10002"]
```

```json
[{"cve_id": "CVE-2024-10001", "cvss": 9.8, "epss": 0.94, "kev": true}]
```

```json
{"cves": ["CVE-2024-10001"]}
```

Values present on the input record are authoritative and are not overwritten by enrichment (a KEV catalog hit can still *promote* `kev` to true).

### Fixtures

Offline signals are read from a fixtures directory (default: bundled `examples/`):

- `kev.json` — a JSON list of ids, or the CISA catalog shape `{"vulnerabilities": [{"cveID": "..."}]}`
- `epss.json` — `{"CVE-...": 0.94}`, or the EPSS API shape `{"data": [{"cve": "...", "epss": "0.94"}]}`
- `nvd.json` — `{"CVE-...": 9.8}`, or a list of `{"cve_id": "...", "cvss": 9.8}` records

Point at your own with `--fixtures path/to/dir`. The bundled example data is clearly-sample (placeholder vendors/products) and lets `rank`/`enrich`/`kev` run out of the box.

## Demos

The [`demos/`](demos/) directory holds twelve self-contained, real-use-case scenarios. Each
folder ships a `scan.json` in the tool's real input format, its own `kev.json` / `epss.json`
/ `nvd.json` fixtures, and a `SCENARIO.md` that narrates where the data came from, the exact
command to run, what to expect, and how to act on it. They are grounded in well-documented,
publicly-known CVEs (Log4Shell, Citrix Bleed, MOVEit, ProxyShell, the Ivanti/Fortinet/
ConnectWise edge bugs, etc.); CVSS base scores and KEV membership are the real published
values, while EPSS figures are clearly-marked illustrative snapshots in the real feed shape.

| Demo | Scenario | Teaches |
| ---- | -------- | ------- |
| [01-log4shell-incident](demos/01-log4shell-incident/) | Morning-after Log4j family triage | KEV escalates the two exploited Log4j bugs to CRITICAL; the DoS/config-only ones stay MED |
| [02-edge-appliance-exposure](demos/02-edge-appliance-exposure/) | Internet-facing VPN/gateway CVEs | When everything is KEV-CRITICAL, the composite *ordering* is the deliverable |
| [03-moveit-supply-chain](demos/03-moveit-supply-chain/) | MOVEit MFT vendor advisory | `enrich` preserves input CVSS, fills EPSS, and promotes KEV from the catalog |
| [04-exchange-proxyshell](demos/04-exchange-proxyshell/) | ProxyLogon + ProxyShell chains | `{"cves":[...]}` + bare-list KEV fixture shapes; `kev` subcommand |
| [05-ci-release-gate](demos/05-ci-release-gate/) | Block-the-build SCA gate | `--fail-on high` exits 2 on a KEV dep but ignores quiet high-CVSS noise |
| [06-scanner-noise-deprioritize](demos/06-scanner-noise-deprioritize/) | Cutting through scanner noise | A CVSS 9.8 quiet bug correctly ranks *below* Log4Shell |
| [07-monthly-kev-review](demos/07-monthly-kev-review/) | BOD 22-01 monthly review | `kev` extracts the due-date-bound shortlist from a mixed backlog |
| [08-bare-cve-ids-baseline](demos/08-bare-cve-ids-baseline/) | Unenriched id list | Fails safe: 0.0 / "no signal", never fabricates severity |
| [09-mixed-vendor-patch-tuesday](demos/09-mixed-vendor-patch-tuesday/) | Cross-vendor patch week | Merges Microsoft/Fortinet/ConnectWise into one defensible order |
| [10-internet-facing-asset-blast](demos/10-internet-facing-asset-blast/) | Asset/exposure-aware triage | Custom `asset`/`exposure` fields survive enrichment for the last-mile call |
| [11-airgap-feeds-enrichment](demos/11-airgap-feeds-enrichment/) | Disconnected / air-gapped triage | `--feeds --offline` enriches from a sneakernet feed snapshot, zero network |
| [12-posture-drift-early-warning](demos/12-posture-drift-early-warning/) | Night-over-night edge-fleet drift | `diff` catches five appliances flipping to KEV/CRITICAL + a decommission, and `--fail-on-drift` gates on it |

Every demo is exercised by the test suite (`tests/test_demos.py`), so each one is guaranteed
to still produce its documented finding.

## Scoring formula

Three normalized inputs, each in `[0, 1]`:

```
cvss_n = clamp(cvss_base / 10, 0, 1)     # base technical severity
epss_n = clamp(epss, 0, 1)               # 30-day exploitation probability
kev    = 1 if CVE in CISA KEV else 0     # known-exploited flag
```

Weighted base (KEV excluded from the weights, so it acts purely as an escalator):

```
base = 100 * (0.6 * cvss_n + 0.4 * epss_n)
```

KEV escalation — known-exploited items are categorically more urgent than CVSS/EPSS alone imply, so KEV both boosts toward 100 and enforces a floor:

```
if kev:
    score = base + 0.5 * (100 - base)    # close half the gap to 100
    score = max(score, 70)               # never below the HIGH floor
```

Final `score` is clamped to `[0, 100]`. Tiers:

| Score    | Tier     |
| -------- | -------- |
| ≥ 90     | CRITICAL |
| ≥ 70     | HIGH     |
| ≥ 40     | MED      |
| else     | LOW      |

The weights and KEV parameters live in `cveintel/scoring.py` (`W_CVSS`, `W_EPSS`, `KEV_BONUS`, `KEV_FLOOR`) and are documented inline. The model is deterministic and fully explainable — every points contribution maps to one of the human-readable `reasons`.

## Features

- `rank` / `enrich` / `kev` / `diff` / `sbom` / `active` subcommands, table or `--json` output
- **Passive SBOM scan** (`sbom`): match a CycloneDX/SPDX/name-list bill of materials against the bundled ~262k-vuln offline corpus, fully offline; CVSS computed from corpus vectors
- **Active mode** (`active`): authorization-gated, read-only banner/header probe of consented in-scope hosts — off by default, requires `--authorized` + `--target-allowlist` + `--rate-limit`, sends no exploits
- `--vulndb` flag on `rank`/`enrich`/`kev`/`diff`: passively backfill missing CVSS from the offline corpus
- Polyglot ports of the core scoring model in **Go / Rust / TypeScript** under `ports/`, each CI-built
- Composite CVSS + KEV + EPSS scoring with plain-language reasons
- KEV escalation (gap-closing boost + HIGH floor)
- **Posture-drift early warning** (`diff`): classifies night-over-night change (KEV-added / tier-up / EPSS-spike / CVSS-up / appeared / resolved), `--worsened-only`, and a `--fail-on-drift` nightly gate — see [`docs/posture-drift.md`](docs/posture-drift.md)
- `--fail-on critical|high` CI/compliance gate (exit code `2`)
- `--sarif` SARIF 2.1.0 export for GitHub code-scanning / dashboards
- Fully offline by default; optional isolated `--live` fetch (NVD / CISA KEV / EPSS)
- Edge / air-gap data-feed cache (`feeds` subcommand): keyless fetch -> disk cache -> offline re-serve, plus tar `snapshot-export`/`snapshot-import` for sneakernet; `rank/enrich/kev/diff --feeds [--offline]`
- Bundled example fixtures; bring-your-own via `--fixtures`
- Twelve real-use-case demos under `demos/`, each test-verified to fire
- Standard library only; real pytest suite (230+ tests, fully offline); GitHub Actions CI for the Python core and for the Go/Rust/TypeScript ports

## Development

```bash
pip install -e ".[dev]"
python -m pytest -q
```

## License

License: COCL 1.0

Maintainer: Cognis Digital

## Bundled vulnerability database

Ships `cveintel/cognis_vulndb.jsonl.gz` — **262,351 real vulnerabilities** (OSV: PyPI/npm/Go/Maven/RubyGems/crates.io/NuGet) with detailed metadata (CVE/GHSA aliases, ecosystem, severity/CVSS, affected packages, dates). Pure-stdlib offline loader `vulndb_local.VulnDB` (`count`/`by_cve`/`by_package`/`search`), air-gap ready. Refresh/extend via `datafeeds.py bulk`.
