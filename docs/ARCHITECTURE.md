# SCATO Architecture

## Overview

SCATO is a lightweight, open-source Software Composition Analysis (SCA) tool. It scans project dependencies for vulnerabilities, generates SBOMs, and enforces security policies.

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
        └──────────┘ └──────────┘  │ Metrics      │  └────────────┘
                                   └──────────────┘
                                          │
                                          ▼
                              ┌──────────────────────┐
                              │   Integrations       │
                              │                      │
                              │ Policy Engine        │
                              │ CI Detection         │
                              │ GitHub (PR, Checks)  │
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
- Returns a flat list of `Dependency` objects

### Phase 2: QUERY
- Batch-queries OSV.dev (primary, free, no API key needed)
- Optionally queries GHSA (needs GitHub token) and NVD (needs API key)
- Enriches with CISA KEV (known exploited vulnerabilities) and EPSS (exploit probability)
- Deduplicates across sources using vulnerability IDs and aliases

### Phase 3: ANALYZE
- Attaches vulnerabilities to dependencies
- Counts severities
- Calculates composite risk score (0-100) with multipliers for KEV, EPSS, direct deps

### Phase 4: OUTPUT
- Terminal report with color-coded severity badges
- JSON report
- SARIF for GitHub Code Scanning
- CycloneDX 1.5 SBOM
- SPDX 2.3 SBOM
- Policy evaluation results

### Phase 5: PERSIST
- Saves scan to local JSON file store (`~/.scato/scans/`)
- Updates scan index for fast history lookups
- CI integration (annotations, outputs, PR comments, check runs)

## Web Server

The built-in web server (`src/server.ts`) uses Hono and provides:

- `GET /` — Serves the built-in dashboard (single-page app)
- `GET /api/health` — Health check
- `POST /api/scan` — Trigger a scan
- `GET /api/scans` — List scan history
- `GET /api/scans/:id` — Get scan details
- `GET /api/trend` — Get vulnerability trend data

The server auto-detects the runtime:
- **Bun**: Uses `Bun.serve()` for native performance
- **Node.js**: Uses `@hono/node-server` adapter

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
3. Add to `Ecosystem` type

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
- **No network without consent** — `--offline` mode for air-gapped environments
- **Secrets via env vars** — API keys never hardcoded or logged
- **Non-root Docker** — container runs as unprivileged user
- **Rate limiting** — respects NVD, GHSA, and EPSS rate limits
