# SCATO Architecture

## Overview

SCATO is a lightweight, open-source Software Composition Analysis (SCA) tool. It scans project dependencies for vulnerabilities, generates SBOMs, and provides a **Prioritized Remediation Plan** so developers can focus on the highest-impact fixes first.

**Design Principles:**
- Zero configuration required
- Works on Node.js 18+ and Bun 1.0+
- No external services needed (databases, caches, etc.)
- Everything optional — core scan works with zero API keys

## System Diagram

```
                    ┌─────────────────────────────────────────────┐
                    │              Entry Points                    │
                    ├──────────┬──────────┬───────────┬───────────┤
                    │   CLI    │ Web UI   │  Docker   │ GH Action │
                    │ index.ts │ serve    │ Container │ action.yml│
                    └────┬─────┴────┬─────┴─────┬─────┴─────┬─────┘
                         │          │           │           │
                         ▼          ▼           ▼           ▼
                    ┌─────────────────────────────────────────────┐
                    │         Scanner Orchestrator                 │
                    │              scanner.ts                      │
                    │                                              │
                    │  DISCOVER → QUERY → ANALYZE → OUTPUT → SAVE │
                    └──────┬──────────────────────────────────┬────┘
                           │                                  │
              ┌────────────┼─────────────────┐                │
              │            │                 │                │
              ▼            ▼                 ▼                ▼
        ┌──────────┐ ┌──────────┐  ┌──────────────┐  ┌────────────┐
        │ Parsers  │ │Advisories│  │  Enrichment  │  │   Output   │
        │          │ │          │  │              │  │            │
        │ npm      │ │ OSV      │  │ EPSS         │  │ Terminal   │
        │ pip      │ │ NVD      │  │ KEV          │  │ JSON       │
        │ go       │ │ GHSA     │  │ GHSA         │  │ SARIF      │
        │ maven    │ │          │  │ NVD          │  │ CycloneDX  │
        │ cargo    │ │Aggregator│  │ Licenses     │  │ SPDX       │
        │ (trans.  │ └──────────┘  │ Metrics      │  └────────────┘
        │  deps)   │                │ Remediation  │
        └──────────┘                └──────────────┘
                                          │
                                          ▼
                              ┌──────────────────────┐
                              │   Integrations       │
                              │   CI Detection       │
                              │   GitHub (PR, Checks)│
                              └──────────────────────┘
                                          │
                                          ▼
                              ┌──────────────────────┐
                              │   Storage            │
                              │   ~/.scato/          │
                              │   JSON file store    │
                              └──────────────────────┘
```

## Scanner Pipeline

The scanner (`src/scanner.ts`) runs a 5-phase pipeline:

### Phase 1: DISCOVER
- Runs all ecosystem parsers in parallel
- Each parser reads lockfiles/manifests from the target directory
- **Transitive dependencies** are resolved where possible (e.g. `poetry.lock`, `Pipfile.lock`, `pipdeptree` for pip; `package-lock.json`, `bun.lock`, `yarn.lock` for npm; `go mod graph` for Go; `mvn dependency:tree` / Gradle for Java; `cargo tree` for Rust)
- Returns a flat list of `Dependency` objects with `isDirect` and `parent` where known

### Phase 2: QUERY
- Batch-queries OSV.dev (primary, free, no API key needed)
- Optionally queries GHSA (needs GitHub token) and NVD (needs API key)
- Enriches with CISA KEV (known exploited vulnerabilities) and EPSS (exploit probability)
- Deduplicates across sources using vulnerability IDs and aliases

### Phase 3: ANALYZE
- Attaches vulnerabilities to dependencies
- Counts severities
- Calculates composite risk score (0–100) with multipliers for KEV, EPSS, direct deps
- **Prioritized Remediation** engine scores each CVE and each package (see below)

### Phase 4: OUTPUT
- Terminal report with color-coded severity badges
- JSON report
- SARIF for GitHub Code Scanning
- CycloneDX 1.5 SBOM
- SPDX 2.3 SBOM

### Phase 5: PERSIST
- Saves scan to local JSON file store (`~/.scato/scans/`)
- Updates scan index for fast history lookups
- CI integration (annotations, outputs, PR comments, check runs)

## Prioritized Remediation Plan

The **Prioritized Remediation Plan** (high-impact remediation) cuts through vulnerability noise by ranking fixes by **risk reduction ROI**. It is implemented in:

- **Server:** `src/enrichment/metrics/remediation.ts` — `computeRemediation(results, topN)`
- **Dashboard:** `src/web/dashboard.ts` — client-side `computeRemediation(vulnResults)` and `renderRemediation(vulnResults)` for immediate UI

**Behavior:**
- Every CVE is scored (max 100 pts) from five weighted components: **KEV (30)**, **EPSS (20)**, **CVSS vector (15)**, **Severity (30)**, **Fix available (5)**. Severity uses an exponential spread (Critical ~33× Low) so a single Critical is not eclipsed by many Lows.
- **Aggregation (fixes "sum of lows"):** Package **base** risk = max(CVE score) + sum(remaining CVE scores) × **DAMPENER** (0.1). Then **adjusted** risk = base × **KEV_MULTIPLIER** (2.5) if the package has any KEV, else base. Total project risk and **Risk Reduction %** use adjusted risks so ROI aligns with ranking.
- Packages are ranked: KEV first, then by adjusted risk score, then by max EPSS, then **fewer CVEs = higher priority** (tie-breaker).
- Top N (default 5) actions include **riskDominator** one-liner ("Driven by: 1 Critical RCE (Network)"), full **score breakdown**, **CVE list**, and **fix coverage**.

**Dashboard display (per package):**
- Fix version and latest registry version (fetched asynchronously via `/api/package-info`)
- Quantified metrics: Risk Score, Risk Reduction %, CVSS/EPSS
- Score breakdown (KEV, EPSS, Vector, Severity, Fix) with percentages
- Risk reduction narrative and threat intelligence (KEV, EPSS, Network RCE)
- CVE table (ID, Severity, CVSS, EPSS, KEV, Score, Fix)
- Ecosystem badge (npm, pip, go, maven, cargo, etc.)

The exact scoring formula and constants are documented in **`docs/REMEDIATION_SCORING.md`**.

## Web Server

The built-in web server (`src/server.ts`) uses Hono and provides:

- `GET /` — Serves the built-in dashboard (single-page app)
- `GET /api/health` — Health check
- `POST /api/scan` — Trigger a scan (body: `{ target }`)
- `GET /api/scans` — List scan history
- `GET /api/scans/:id` — Get scan report by ID
- `GET /api/package-info?ecosystem=&name=` — Package description and **latest version** from the registry (used by the Prioritized Remediation card and dependency details)
- `GET /api/trend` — Get vulnerability trend data (query: `target`, `days`)

**Package-info registries (all ecosystems):**
- **npm** — registry.npmjs.org (`dist-tags.latest`)
- **pip** — pypi.org (`info.version`)
- **go** — proxy.golang.org (`@v/list` or `@latest`)
- **maven** — search.maven.org Solr (`latestVersion`)
- **cargo** — crates.io (`crate.newest_version`)
- **nuget** — api.nuget.org v3 flat container
- **gem** — rubygems.org API
- **composer** — repo.packagist.org p2

The server auto-detects the runtime:
- **Bun:** Uses `Bun.serve()` for native performance
- **Node.js:** Uses `@hono/node-server` adapter

## Dashboard

The dashboard (`src/web/dashboard.ts`) is a single-page app served at `/`:

- **Scan:** User enters a target path and runs a scan; results replace the welcome view.
- **Results:** Stats bar (dependencies, vulnerabilities, KEV, Critical/High/Medium/Low), Risk Assessment meter, **Prioritized Remediation Plan** card (summary box + top N actions with latest version, score breakdown, CVE table), then tabs:
  - **Vulnerabilities** — Sort (severity, KEV first, EPSS) and filter (e.g. KEV only); click a row for CVE detail (KEV dates, EPSS, CVSS vector, fix).
  - **Dependencies** — Same sort/filter by KEV; list and dependency tree view with Unicode tree characters; click a dependency for tree and package info (including latest version via `/api/package-info`).
- **No demo/sample mode** — all data comes from real scans.

## Storage

SCATO uses a zero-dependency JSON file store:

```
~/.scato/
├── scan-index.json     # Lightweight index of all scans
├── scans/
│   ├── <uuid>.json     # Full scan reports
│   └── ...
└── cache/
    ├── <source>_<id>.json  # Vulnerability cache with TTL
    └── ...
```

No database server, no native modules, no setup.

## Extension Points

### New Ecosystem Parser
1. Create `src/core/parsers/neweco.ts` implementing `parse(dir) → ParserResult`
2. Add to `PARSERS` array in `src/core/parsers/index.ts`
3. Add to `Ecosystem` type in `src/types.ts`
4. Optionally add latest-version support in `GET /api/package-info` in `src/server.ts`

### New Vulnerability Source
1. Create adapter in `src/enrichment/advisories/`
2. Add to `queryAllSources()` in `src/core/advisories/aggregator.ts`

### New Output Format
1. Create formatter in `src/core/output/` or `src/sbom/`
2. Wire into scanner output phase

## Performance

- **Parallel parsing** — all ecosystems parsed concurrently
- **Batched OSV queries** — up to 1000 packages per batch request
- **Concurrent enrichment** — GHSA queries run 5 at a time
- **In-memory caching** — KEV catalog cached for 4 hours
- **JSON file store** — no database overhead
- **Dynamic imports** — optional modules loaded only when needed

## Security Model

- **No code execution** — only parses manifest/lockfiles, never runs user code
- **Safe subprocess calls** — parsers that need CLI tools (e.g. `pipdeptree`, `go mod graph`, `mvn dependency:tree`, `cargo tree`) use `execFileSync` with argument arrays; no shell interpolation (CWE-78 mitigation)
- **No network without consent** — `--offline` mode for air-gapped environments
- **Secrets via env vars** — API keys never hardcoded or logged
- **Non-root Docker** — container runs as unprivileged user
- **Rate limiting** — respects NVD, GHSA, and EPSS rate limits

## Related Documentation

- **`docs/REMEDIATION_SCORING.md`** — Scoring algorithm for the Prioritized Remediation Plan (weights, CVSS vector breakdown, severity map, formulas).
