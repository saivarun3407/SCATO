# SCATO

**Software Composition Analysis Tool** — find vulnerabilities, generate SBOMs, and enforce security policies across your dependencies.

Open source. Lightweight. Works everywhere.

---

## Features

- **Multi-Ecosystem** — npm, pip, Go, Maven, Cargo out of the box
- **5 Vulnerability Sources** — OSV, NVD, GHSA, CISA KEV, EPSS
- **SBOM Generation** — CycloneDX 1.5 and SPDX 2.3
- **Policy Engine** — block builds on severity, CVSS, KEV, EPSS, copyleft licenses
- **Web Dashboard** — built-in UI at `localhost:3001`, zero setup
- **CI/CD Ready** — GitHub Actions, GitLab CI, Jenkins, Azure Pipelines, CircleCI
- **SARIF Output** — integrates with GitHub Code Scanning
- **License Detection** — flags copyleft and unknown licenses
- **Risk Scoring** — composite 0-100 score with KEV/EPSS multipliers
- **Fast** — parallel parsing, batched API calls, local JSON cache

---

## Quick Start

### Option 1: npx (zero install)

```bash
npx scato scan .
```

### Option 2: Install globally

```bash
npm install -g scato
scato scan /path/to/project
```

### Option 3: Bun

```bash
bun install -g scato
scato scan .
```

### Option 4: Docker

```bash
docker run --rm -v $(pwd):/scan scato/scato scan /scan
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

### Policy

```bash
scato policy-init                      # Generate default policy file
scato scan . --policy .scato-policy.json  # Scan with policy enforcement
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: SCATO Security Scan
  uses: scato/scato@v3
  with:
    fail-on: high
    sarif: true
    sbom: true
    pr-comment: true
```

### GitLab CI

```yaml
security-scan:
  image: scato/scato:latest
  script:
    - scato scan . --json > report.json --sarif report.sarif
  artifacts:
    reports:
      sast: report.sarif
```

### Generic CI

```bash
npx scato scan . --ci --fail-on high --json > scato-report.json
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

1. **Discover** — Parses lockfiles/manifests (package-lock.json, requirements.txt, go.sum, pom.xml, Cargo.lock)
2. **Query** — Batch-queries OSV.dev, then enriches with NVD, GHSA, KEV, EPSS
3. **Analyze** — Deduplicates, calculates risk scores, evaluates policies
4. **Output** — Terminal report, JSON, SARIF, CycloneDX SBOM, SPDX SBOM
5. **Persist** — Saves to local JSON store for history and trend analysis

---

## Supported Ecosystems

| Ecosystem | Files Parsed |
|-----------|-------------|
| npm | `package-lock.json`, `package.json` |
| pip | `Pipfile.lock`, `requirements.txt` |
| Go | `go.sum`, `go.mod` |
| Maven | `pom.xml` |
| Cargo | `Cargo.lock`, `Cargo.toml` |

---

## Docker

```bash
# Build
docker build -t scato .

# Scan a directory
docker run --rm -v $(pwd):/scan scato scan /scan

# Run the web dashboard
docker run --rm -p 3001:3001 scato serve --port 3001
```

Or use Docker Compose:

```bash
docker-compose up
# Dashboard at http://localhost:3001
```

---

## Development

```bash
git clone https://github.com/scato/scato.git
cd scato
bun install
bun run dev            # Watch mode
bun run typecheck      # Type checking
bun test               # Run tests
```

---

## License

MIT
