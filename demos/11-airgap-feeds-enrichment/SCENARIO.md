# Demo 11 — Air-gap enrichment from the data-feed cache

A disconnected / air-gapped triage workstation has no internet egress, but it
**does** have a feed snapshot that was sneakernetted in from a connected host.
cveintel enriches a bare CVE list (`scan.json`) entirely from the cached
`cisa-kev` / `epss` / `nvd-cve` feeds — **zero network**.

The committed cache lives at `../../tests/fixtures/feeds-cache/` (trimmed,
real-shaped CISA KEV / FIRST EPSS / NIST NVD payloads).

## On the CONNECTED host — capture a snapshot

```bash
# Refresh the three feeds cveintel consumes, then tar them for sneakernet.
cveintel feeds update                       # cisa-kev epss nvd-cve
cveintel feeds snapshot-export feeds.tar.gz
```

## On the AIR-GAPPED host — rehydrate + enrich offline

```bash
export COGNIS_FEEDS_CACHE=/srv/cveintel/feed-cache
cveintel feeds snapshot-import feeds.tar.gz   # one-time, from the USB drive
cveintel feeds list                            # confirm cache freshness

# Enrich + rank with NO network access:
cveintel rank scan.json --feeds --offline
```

## Run this demo as-is (points the cache env at the committed fixtures)

```bash
COGNIS_FEEDS_CACHE=tests/fixtures/feeds-cache \
  cveintel rank demos/11-airgap-feeds-enrichment/scan.json --feeds --offline
```

Expected: Log4Shell (CVE-2021-44228), MOVEit (CVE-2023-34362), and the
PAN-OS GlobalProtect bug (CVE-2024-3400) all land **CRITICAL** — KEV-listed,
near-1.0 EPSS, CVSS 9.8–10.0 — while CVE-2024-99999 (not in KEV, low EPSS)
ranks below them. Every signal came from the offline cache.
