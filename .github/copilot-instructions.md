# SCATO Copilot Instructions

SCATO is an enterprise-grade Software Composition Analysis (SCA) tool that detects vulnerabilities, generates SBOMs, and enforces security policies across multiple package ecosystems.

## Architecture Overview

SCATO follows a **modular pipeline architecture** with clear phase separation:

1. **Parse Phase**: `src/parsers/` — Discover dependencies across ecosystems (npm, pip, go, maven, cargo)
2. **Enrich Phase**: License detection from `src/license/detector.ts`
3. **Export Phase**: `src/advisories/aggregator.ts` — Query multiple vulnerability sources in priority order
4. **Build Phase**: Aggregate into `ScanResult[]` objects
5. **Augment Phase**: Generate SBOM (CycloneDX), metrics, policy evaluation
6. **Report Phase**: Output to terminal, JSON, SARIF formats via `src/reporter/`

The **main orchestrator** is `src/scanner.ts::scan()` — all new features must integrate here.

## Core Patterns & Conventions

### Source Aggregation Pattern
**Where**: `src/advisories/aggregator.ts` and individual source files (`nvd.ts`, `osv.ts`, `ghsa.ts`, `kev.ts`, `epss.ts`)

- **OSV is primary** (always enabled): free, comprehensive, cross-ecosystem
- **NVD supplements OSV** (optional): national vulnerability database, needs API key
- **GHSA adds GitHub context** (optional): requires GitHub token, queries direct dependencies
- **KEV enriches**: marks CISA Known Exploited Vulnerabilities
- **EPSS enriches**: adds exploitation probability scores

**Key:** Deduplication by ID and aliases prevents re-reporting. Check `existingIds` set before adding (see `aggregator.ts` line 50+).

### Parser Pattern
**Where**: `src/parsers/` — One file per ecosystem

Each parser follows this contract:
- Try manifest lockfile first (e.g., `package-lock.json` for npm) — has transitive deps
- Fall back to source manifest (e.g., `package.json`) — direct deps only
- Return `ParserResult { ecosystem, file, dependencies[] }`
- Mark `isDirect` flag based on root manifest presence
- Generate `purl` (Package URL) for SBOM compliance: `pkg:npm/name@version`

Example: `src/parsers/npm.ts` checks `package-lock.json` (lockfileVersion 1/2/3), then `package.json`.

### Type-First Development
**Where**: `src/types.ts` — single source of truth

All domain objects defined there:
- `Dependency`: name, version, ecosystem, isDirect, license, purl, scope ("runtime"|"dev"|"optional"|"peer")
- `Vulnerability`: id, severity, source, cvssScore, epssScore, isKnownExploited
- `ScanReport`: aggregates all results with metrics and policy evaluation
- `PolicyRule`: condition-based rules (e.g., "max_severity", "no_kev", "max_epss")

When adding features, define types first in `types.ts`.

### CLI Design (Commander Pattern)
**Where**: `src/index.ts`

Uses Commander for argument/option parsing. All options map to `ScanOptions` interface:
- Add new option with `.option()` chain
- Pass through scanner as `ScanOptions` property
- Default values in `ScanOptions` interface, not Commander

Example: `--fail-on <severity>` → `options.failOn` → `ScanOptions.failOn`

## Key Workflows & Commands

```bash
# Development
bun --watch src/index.ts          # Auto-rebuild on changes
bun src/index.ts scan             # Direct execution
bun src/index.ts scan . --json    # JSON output

# Production build
bun build src/index.ts --outdir dist --target node  # Creates dist/index.js (CLI entry point)

# Type checking
tsc --noEmit                      # Verify TypeScript

# Dashboard
bun src/server.ts                 # Runs web UI on port 3000+ (Vite React app)
bun src/server.ts & cd web && bun run dev  # Full stack
```

## High-Value Code Locations

| Feature | File | Purpose |
|---------|------|---------|
| Scan orchestration | `src/scanner.ts` | Main entry point for features; coordinates all subsystems |
| Vulnerability merging | `src/advisories/aggregator.ts` | Deduplication logic; source priority |
| Policy rules | `src/policy/engine.ts` | Default policies, rule evaluation (max_severity, no_kev, etc.) |
| Terminal output | `src/reporter/terminal.ts` | Severity badges, metrics display, charm formatting |
| GitHub integration | `src/github/integration.ts` | PR comments, check runs, GitHub context detection |
| CI detection | `src/ci/detect.ts` | Auto-detect GitHub Actions, GitLab CI, etc. |
| CycloneDX SBOM | `src/sbom/cyclonedx.ts` | SBOM generation; follows CycloneDX 1.4 spec |
| SARIF reporting | `src/reporter/sarif.ts` | GitHub code scanning format |

## Integration Points & APIs

### External Services
- **OSV API** (`src/advisories/osv.ts`): Query `https://api.osv.dev/v1/query` — rate limit ~1000/day, no auth
- **NVD API** (`src/advisories/nvd.ts`): Query `https://services.nvn.nist.gov/rest/json/nvdcve/` — requires API key for rate lifting
- **GHSA GraphQL** (`src/advisories/ghsa.ts`): GitHub token required; queries package vulnerabilities
- **CISA KEV** (`src/advisories/kev.ts`): Known Exploited Vulnerabilities catalog — free, curated

### GitHub Action Integration
Entry point: `src/index.ts` (default scan command)

GitHub Actions invokes via composite action (`action.yml`):
1. Sets up Bun runtime
2. Installs dependencies
3. Runs scan
4. Outputs: `total_vulnerabilities`, `risk_score`, `policy_passed`, `sbom_file`, `sarif_file`

**Pass context:** `--pr-comment`, `--check-run` flags enable GitHub integration when `GITHUB_TOKEN` available.

## Development Considerations

### Adding a New Ecosystem Parser
1. Create `src/core/parsers/newecosystem.ts`
2. Export `parseNewEcosystem(dir): Promise<ParserResult|null>`
3. Add to `src/core/parsers/index.ts` (PARSERS array and discoverDependencies)
4. Add ecosystem to `Ecosystem` in `types.ts`

### Adding a New Vulnerability Source
1. Create `src/enrichment/advisories/newsource.ts` with query function
2. Import and call in `src/core/advisories/aggregator.ts`
3. Deduplicate by ID + aliases against existing vulns
4. Add source to `VulnerabilitySource` in `types.ts`

### Adding a New Reporter Format
1. Create reporter in `src/core/output/` or `src/integrations/ci/`
2. Call from `src/scanner.ts` Phase 4 (OUTPUT)
3. Add CLI option in `src/index.ts`

### Testing Policy Rules
Policy rules are in `src/integrations/policy/engine.ts::evaluatePolicy()`. Default rules in `DEFAULT_POLICY` include:
- `no-critical`: Block if max severity >= CRITICAL
- `no-kev`: Block if any vuln in CISA KEV
- `epss-threshold`: Warn if EPSS score > threshold
- `copyleft-check`: Warn on GPL/AGPL licensed deps

Add new rules following `PolicyRule { id, name, condition }` pattern.

## File Organization Rules

- **Types**: Always in `src/types.ts`, never scatter interfaces
- **Each concern separate**: `parsers/`, `advisories/`, `reporters/`, `policy/` are standalone
- **No circular imports**: Scanner imports subsystems, subsystems don't import scanner
- **Async throughout**: All I/O operations are async; use Promises consistently
- **Error handling**: Catch failures in aggregator (partial results OK); always return something

## Common Patterns to Reuse

```typescript
// Deduplication pattern (src/advisories/aggregator.ts)
const existingIds = new Set(existing.flatMap(v => [v.id, ...v.aliases]));
for (const newVuln of newResults) {
  const isDuplicate = existingIds.has(newVuln.id) || 
    newVuln.aliases.some(a => existingIds.has(a));
  if (!isDuplicate) existing.push(newVuln);
}

// Manifest discovery pattern (src/parsers/)
try {
  const content = await readFile(lockPath, "utf-8");
  return parseLockfile(content, lockPath);
} catch {
  // fall back to source manifest
  return parseSourceFile(content, srcPath);
}

// Spinner pattern (src/index.ts)
const spinner = !options.json && !isCI 
  ? ora({ text: "...", indent: 2 }).start() 
  : null;
if (spinner) spinner.text = "Next phase...";
if (spinner) spinner.succeed("Completed");
```

## Severity Levels & EPSS Scoring

- **Severity**: CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN (from `SEVERITY_ORDER` in `policy/engine.ts`)
- **EPSS Score**: 0.0–1.0 representing exploitation probability; used as enrichment and policy threshold
- **KEV Flag**: Boolean `isKnownExploited`; highest priority in policy and reporting

Terminal reporter uses severity-based coloring via `SEVERITY_COLORS` map (chalk formatting).

## Performance Considerations

- **Parser phase**: Parallel across ecosystems via `Promise.all()`
- **Advisory phase**: Batched API calls (GHSA uses batch queries, NVD respects rate limits)
- **Deduplication**: Use Sets and early continues to avoid O(n²) lookups
- **Cache**: Database stores historical scans in `src/db/database.ts`; results can be cached per dependency+source combination

When adding new sources, implement rate limiting and respect API timeouts (default 30s in `aggregator.ts`).
