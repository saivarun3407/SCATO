# SCATO

**Software Composition Analysis Tool** — find vulnerabilities, generate SBOMs, and analyze your dependencies.

Open source. Lightweight. Works everywhere.

---

## Features

- **Multi-Ecosystem** — npm, pip, Go, Maven/Gradle, Cargo out of the box
- **5 Vulnerability Sources** — OSV, NVD, GHSA, CISA KEV, EPSS
- **SBOM Generation** — CycloneDX 1.5 and SPDX 2.3
- **Web Dashboard** — built-in UI at `localhost:3001` with KEV sort/filter, dependency tree, and demo mode
- **CI/CD Ready** — GitHub Actions, GitLab CI, Azure Pipelines
- **SARIF Output** — integrates with GitHub Code Scanning
- **License Detection** — flags copyleft and unknown licenses
- **Risk Scoring** — composite 0-100 score with KEV/EPSS multipliers
- **Transitive Dependency Tree** — full parent-child mapping across all ecosystems
- **Fast** — parallel parsing, batched API calls, local JSON cache

---

## Quick Start

### Option 1: Clone and run

```bash
git clone https://github.com/saivarun3407/SCATO.git
cd SCATO
bun install
bun run build
node dist/index.js scan .
```

### Option 2: Docker

```bash
docker build -t scato .
docker run --rm -v $(pwd):/scan scato scan /scan
```

---

## Web Dashboard

Start the built-in web UI:

```bash
scato serve
# Dashboard opens at http://localhost:3001
```

Options:

```bash
scato serve --port 8080      # Custom port
scato serve --open            # Auto-open browser
```

The dashboard lets you:
- Run scans from the browser (point at any local directory)
- View results with severity badges, fix suggestions, and risk scores
- Sort and filter by KEV (known exploited), EPSS, severity
- Browse the dependency tree with parent-child relationships
- Click any dependency to see description, latest version, and subtree
- Load demo data to preview all features
- Browse scan history
- Export JSON reports and SBOMs

---

## CLI Usage

### Scan

```bash
# Basic scan
scato scan .

# JSON output
scato scan . --json

# Generate SBOM
scato scan . --sbom sbom.json

# Generate SARIF (for GitHub Code Scanning)
scato scan . --sarif results.sarif

# Specific ecosystems only
scato scan . --ecosystem npm pip

# Skip dev dependencies
scato scan . --skip-dev

# Fail on medium or above
scato scan . --fail-on medium

# Choose vulnerability sources
scato scan . --sources osv kev epss nvd ghsa

# Full options
scato scan --help
```

### SBOM

```bash
scato sbom .                           # CycloneDX (default)
scato sbom . --format spdx             # SPDX 2.3
scato sbom . --output my-sbom.json     # Custom output path
```

### History & Trends

```bash
scato history                          # View recent scans
scato trend /path/to/project           # View vulnerability trend
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: SCATO Security Scan
  uses: saivarun3407/SCATO@main
  with:
    fail-on: high
    sarif: true
    sbom: true
```

### Generic CI

```bash
# Clone and run in your CI pipeline
git clone https://github.com/saivarun3407/SCATO.git
cd SCATO && bun install && bun run build
node dist/index.js scan /path/to/project --ci --fail-on high --json > scato-report.json
```

---

## Configuration

SCATO works with **zero configuration**. Optional environment variables:

| Variable | Purpose |
|----------|---------|
| `SCATO_PORT` | Web dashboard port (default: 3001) |
| `SCATO_DATA_DIR` | Data storage directory (default: `~/.scato`) |
| `NVD_API_KEY` | NVD API key for better rate limits |
| `GITHUB_TOKEN` | GitHub token for GHSA data + PR comments |

---

## How It Works

```
DISCOVER → QUERY → ANALYZE → OUTPUT → PERSIST
```

1. **Discover** — Parses lockfiles/manifests across 5 ecosystems with full transitive dependency resolution
2. **Query** — Batch-queries OSV.dev, then enriches with NVD, GHSA, KEV, EPSS
3. **Analyze** — Deduplicates, calculates risk scores, builds dependency trees
4. **Output** — Terminal report, JSON, SARIF, CycloneDX SBOM, SPDX SBOM
5. **Persist** — Saves to local JSON store for history and trend analysis

---

## Supported Ecosystems

| Ecosystem | Files Parsed |
|-----------|-------------|
| npm | `package-lock.json`, `bun.lock`, `yarn.lock`, `package.json` |
| pip | `poetry.lock`, `Pipfile.lock`, `requirements.txt`, + `pipdeptree`/`pip show`/site-packages metadata |
| Go | `go.sum`, `go.mod`, + `go mod graph` for dependency tree |
| Maven/Gradle | `pom.xml`, `gradle.lockfile`, `build.gradle`, `build.gradle.kts`, + `mvn dependency:tree`/`gradle dependencies` |
| Cargo | `Cargo.lock`, `Cargo.toml`, + `cargo tree` for dependency tree |

---

## Docker

```bash
# Build locally
docker build -t scato .

# Scan a directory
docker run --rm -v $(pwd):/scan scato scan /scan

# Run the web dashboard
docker run --rm -p 3001:3001 scato serve --port 3001
```

---

## Development

```bash
git clone https://github.com/saivarun3407/SCATO.git
cd SCATO
bun install
bun run build          # Build to dist/
bun run dev            # Watch mode
bun run typecheck      # Type checking
bun test               # Run tests
```

---

## License

MIT
