# SCATO Quick Start

Get scanning in under 60 seconds.

## 1. Install

Pick one:

```bash
# No install needed (npx)
npx scato scan .

# Or install globally
npm install -g scato

# Or with Bun
bun install -g scato
```

## 2. Scan

```bash
# Scan current directory
scato scan .

# Scan a specific project
scato scan /path/to/your/project

# Get JSON output
scato scan . --json
```

## 3. Web Dashboard (optional)

```bash
scato serve --open
# Opens http://localhost:3001 in your browser
```

## 4. Generate SBOM (optional)

```bash
scato sbom . --output sbom.json
```

## 5. CI Integration (optional)

Add to your GitHub Actions workflow:

```yaml
- uses: scato/scato@v3
  with:
    fail-on: high
    sarif: true
```

## That's It

- No database to set up
- No API keys required (optional for enhanced data)
- No configuration files needed
- Works with Node.js 18+ or Bun 1.0+

See [README.md](README.md) for full documentation.
