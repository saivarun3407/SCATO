# Contributing to SCATO

Thank you for your interest in contributing! This document will help you get started.

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org) 18+ or [Bun](https://bun.sh) 1.0+
- Git

### Setup

```bash
git clone https://github.com/YOUR_USERNAME/scato.git
cd scato
bun install          # or: npm install
bun run dev          # Watch mode (Bun)
```

### Run a Scan

```bash
bun src/index.ts scan /path/to/project
```

### Start the Web Dashboard

```bash
bun src/index.ts serve --open
```

### Run Tests

```bash
bun test
bun run typecheck
```

## Architecture

SCATO follows a pipeline architecture:

```
Parsers → Advisories → Enrichment → Metrics → Output
```

### Directory Structure

| Directory | Purpose |
|-----------|---------|
| `src/index.ts` | CLI entry point (Commander) |
| `src/scanner.ts` | Core scan orchestrator (5-phase pipeline) |
| `src/server.ts` | HTTP server + REST API (Hono) |
| `src/types.ts` | Shared TypeScript types |
| `src/core/parsers/` | Ecosystem parsers (npm, pip, go, maven, cargo) |
| `src/core/advisories/` | Vulnerability sources (OSV, aggregator) |
| `src/core/output/` | Terminal and JSON reporters |
| `src/enrichment/advisories/` | Optional enrichment (EPSS, GHSA, KEV, NVD) |
| `src/enrichment/license/` | License detection |
| `src/enrichment/metrics/` | Risk score calculator |
| `src/integrations/ci/` | CI platform detection, SARIF output |
| `src/integrations/github/` | GitHub PR comments, check runs |
| `src/integrations/policy/` | Policy engine |
| `src/sbom/` | CycloneDX and SPDX SBOM generators |
| `src/storage/` | JSON file storage for history/cache |
| `src/web/` | Built-in web dashboard |
| `test/` | Test files and fixtures |

### Adding a New Ecosystem Parser

1. Create `src/core/parsers/newecosystem.ts`
2. Add to the `PARSERS` array in `src/core/parsers/index.ts`
3. Add to the `Ecosystem` type in `src/types.ts`
4. Add test fixtures in `test/fixtures/newecosystem/`

### Adding a New Vulnerability Source

1. Create `src/enrichment/advisories/newsource.ts`
2. Add to `queryAllSources()` in `src/core/advisories/aggregator.ts`
3. Add to `VulnerabilitySource` type in `src/types.ts`

### Adding a New Output Format

1. Create the formatter in `src/core/output/` or `src/sbom/`
2. Call it from the output phase in `src/scanner.ts`
3. Add a CLI option in `src/index.ts`

## Code Standards

- **TypeScript strict mode** — no `any` unless absolutely necessary
- **async/await** — no callback-style code
- **Error handling** — use try/catch, fail gracefully with `catch { /* optional */ }`
- **Naming** — camelCase for functions, PascalCase for types, UPPER_SNAKE for constants
- **Files** — one concern per file, no circular imports

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `refactor:` Code cleanup
- `test:` Tests
- `chore:` Maintenance

## Pull Request Process

1. Fork and create a feature branch
2. Make your changes
3. Run `bun run typecheck` and `bun test`
4. Submit a PR with a clear description

Thank you for contributing!
