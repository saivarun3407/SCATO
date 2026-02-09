# SCATO Quick Start

Get scanning in under 60 seconds.

## 1. Install

```bash
git clone https://github.com/saivarun3407/SCATO.git
cd SCATO
bun install
bun run build
```

## 2. Scan

```bash
# Scan current directory
node dist/index.js scan .

# Scan a specific project
node dist/index.js scan /path/to/your/project

# Get JSON output
node dist/index.js scan . --json
```

## 3. Web Dashboard (optional)

```bash
node dist/index.js serve --open
# Opens http://localhost:3001 in your browser
```

## 4. Generate SBOM (optional)

```bash
node dist/index.js sbom . --output sbom.json
```

## 5. CI Integration (optional)

Add to your GitHub Actions workflow:

```yaml
- uses: saivarun3407/SCATO@main
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
