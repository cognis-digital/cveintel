# cveintel

**CVE enrichment + prioritization CLI** — correlate base severity (CVSS), known-exploited status (CISA KEV), and exploitation probability (EPSS) into a single explained "patch these first, here's why" ranking. Works fully offline on fixture JSON; optionally fetches live data.

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

The [`demos/`](demos/) directory holds ten self-contained, real-use-case scenarios. Each
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

- `rank` / `enrich` / `kev` subcommands, table or `--json` output
- Composite CVSS + KEV + EPSS scoring with plain-language reasons
- KEV escalation (gap-closing boost + HIGH floor)
- `--fail-on critical|high` CI/compliance gate (exit code `2`)
- `--sarif` SARIF 2.1.0 export for GitHub code-scanning / dashboards
- Fully offline by default; optional isolated `--live` fetch (NVD / CISA KEV / EPSS)
- Bundled example fixtures; bring-your-own via `--fixtures`
- Ten real-use-case demos under `demos/`, each test-verified to fire
- Standard library only; real pytest suite; GitHub Actions CI

## Development

```bash
pip install -e ".[dev]"
python -m pytest -q
```

## License

License: COCL 1.0

Maintainer: Cognis Digital
