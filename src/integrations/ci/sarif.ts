// ─── SARIF Output Generator ───
// Static Analysis Results Interchange Format (SARIF) v2.1.0
// Compatible with GitHub Code Scanning, Azure DevOps, VS Code

import type { ScanReport, SarifLog, SarifRun, SarifRule, SarifResult, Severity } from "../../types.js";
import { writeFile } from "fs/promises";

const SEVERITY_TO_SARIF: Record<Severity, "error" | "warning" | "note"> = {
  CRITICAL: "error",
  HIGH: "error",
  MEDIUM: "warning",
  LOW: "note",
  UNKNOWN: "note",
};

const ECOSYSTEM_MANIFEST: Record<string, string> = {
  npm: "package.json",
  pip: "requirements.txt",
  go: "go.mod",
  maven: "pom.xml",
  cargo: "Cargo.toml",
  nuget: "packages.config",
  gem: "Gemfile",
  composer: "composer.json",
};

export function generateSarif(report: ScanReport): SarifLog {
  const rules: SarifRule[] = [];
  const results: SarifResult[] = [];
  const ruleIndex = new Map<string, number>();

  for (const scanResult of report.results) {
    for (const vuln of scanResult.vulnerabilities) {
      // Add rule if not already present
      if (!ruleIndex.has(vuln.id)) {
        ruleIndex.set(vuln.id, rules.length);
        rules.push({
          id: vuln.id,
          name: vuln.id.replace(/[^a-zA-Z0-9]/g, ""),
          shortDescription: {
            text: vuln.summary || `Vulnerability ${vuln.id}`,
          },
          fullDescription: vuln.details
            ? { text: vuln.details.slice(0, 1000) }
            : undefined,
          helpUri: vuln.references?.[0],
          defaultConfiguration: {
            level: SEVERITY_TO_SARIF[vuln.severity],
          },
        });
      }

      // Add result
      const dep = scanResult.dependency;
      const manifest = ECOSYSTEM_MANIFEST[dep.ecosystem] || "package.json";

      let message = `${vuln.id}: ${dep.name}@${dep.version} — ${vuln.summary || "No description"}`;
      if (vuln.fixed_version) {
        message += ` (fix: upgrade to ${vuln.fixed_version})`;
      }
      if (vuln.isKnownExploited) {
        message += " [CISA KEV: Actively Exploited]";
      }
      if (vuln.epssScore) {
        message += ` [EPSS: ${(vuln.epssScore * 100).toFixed(1)}%]`;
      }

      results.push({
        ruleId: vuln.id,
        level: SEVERITY_TO_SARIF[vuln.severity],
        message: { text: message },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: manifest,
              },
            },
          },
        ],
      });
    }
  }

  const run: SarifRun = {
    tool: {
      driver: {
        name: "SCATO",
        version: report.version,
        informationUri: "https://github.com/scato/scato",
        rules,
      },
    },
    results,
  };

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [run],
  };
}

export async function writeSarif(report: ScanReport, outputPath: string): Promise<void> {
  const sarif = generateSarif(report);
  await writeFile(outputPath, JSON.stringify(sarif, null, 2));
}
