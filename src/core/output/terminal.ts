// ─── Terminal Reporter ───
// CLI output: severity badges, metrics, policy results. License via dynamic import.

import chalk from "chalk";
import type { ScanReport, ScanResult, Severity } from "../../types.js";

const SEVERITY_COLORS: Record<Severity, (s: string) => string> = {
  CRITICAL: chalk.bgRed.white.bold,
  HIGH: chalk.red.bold,
  MEDIUM: chalk.yellow,
  LOW: chalk.blue,
  UNKNOWN: chalk.gray,
};

export async function printReport(report: ScanReport): Promise<void> {
  console.log();
  console.log(chalk.cyan.bold("╔══════════════════════════════════════════════════════════════╗"));
  console.log(chalk.cyan.bold("║") + chalk.white.bold("  SCATO — Software Composition Analysis Tool                 ") + chalk.cyan.bold("║"));
  console.log(chalk.cyan.bold("║") + chalk.gray("  v3.0.0 | OSV · NVD · GHSA · KEV · EPSS                      ") + chalk.cyan.bold("║"));
  console.log(chalk.cyan.bold("╚══════════════════════════════════════════════════════════════╝"));
  console.log();

  // Summary
  console.log(chalk.white.bold("  Target:       ") + chalk.cyan(report.target));
  console.log(chalk.white.bold("  Ecosystems:   ") + report.ecosystems.join(", "));
  console.log(chalk.white.bold("  Dependencies: ") + chalk.yellow(String(report.totalDependencies)));
  console.log(chalk.white.bold("  Scan time:    ") + chalk.gray(report.timestamp));

  if (report.scanDurationMs) {
    console.log(chalk.white.bold("  Duration:     ") + chalk.gray(`${(report.scanDurationMs / 1000).toFixed(1)}s`));
  }
  console.log();

  // Severity summary bar
  printSeveritySummary(report);

  // Metrics block
  if (report.metrics) {
    printMetrics(report);
  }

  if (report.totalVulnerabilities === 0) {
    console.log();
    console.log(chalk.green.bold("  ✓ No known vulnerabilities found!"));
    console.log();
  } else {
    console.log();

    // KEV warnings (highest priority)
    printKEVWarnings(report);

    // Group results by severity
    const vulnResults = report.results.filter((r) => r.vulnerabilities.length > 0);
    const sortedResults = vulnResults.sort((a, b) => {
      const severityOrder: Record<Severity, number> = {
        CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4,
      };
      const aSev = a.vulnerabilities[0]?.severity || "UNKNOWN";
      const bSev = b.vulnerabilities[0]?.severity || "UNKNOWN";
      return severityOrder[aSev] - severityOrder[bSev];
    });

    for (const result of sortedResults) {
      printVulnerablePackage(result);
    }
  }

  // License summary
  await printLicenseSummary(report);

  // Policy results
  if (report.policyResult) {
    printPolicyResults(report);
  }

  // Footer
  console.log();
  console.log(chalk.gray("  ─────────────────────────────────────────────"));
  if (report.sbomPath) {
    console.log(chalk.gray(`  SBOM: ${report.sbomPath}`));
  }

  const sources: string[] = [];
  if (report.dataSourceTimestamps) {
    sources.push(...Object.keys(report.dataSourceTimestamps).map((s) => s.toUpperCase()));
  }
  if (sources.length > 0) {
    console.log(chalk.gray(`  Data sources: ${sources.join(", ")}`));
  } else {
    console.log(chalk.gray("  Data: OSV.dev (NVD, GitHub Advisory, PyPI, RustSec, Go)"));
  }

  if (report.scanId) {
    console.log(chalk.gray(`  Scan ID: ${report.scanId}`));
  }
  console.log();
}

function printSeveritySummary(report: ScanReport): void {
  const counts = report.severityCounts;
  const parts: string[] = [];

  if (counts.CRITICAL > 0)
    parts.push(SEVERITY_COLORS.CRITICAL(` ${counts.CRITICAL} CRITICAL `));
  if (counts.HIGH > 0)
    parts.push(SEVERITY_COLORS.HIGH(` ${counts.HIGH} HIGH `));
  if (counts.MEDIUM > 0)
    parts.push(SEVERITY_COLORS.MEDIUM(` ${counts.MEDIUM} MEDIUM `));
  if (counts.LOW > 0)
    parts.push(SEVERITY_COLORS.LOW(` ${counts.LOW} LOW `));
  if (counts.UNKNOWN > 0)
    parts.push(SEVERITY_COLORS.UNKNOWN(` ${counts.UNKNOWN} UNKNOWN `));

  if (parts.length > 0) {
    console.log("  " + parts.join("  "));
  }
}

function printMetrics(report: ScanReport): void {
  const m = report.metrics!;
  console.log();
  console.log(chalk.white.bold("  ─── Risk Assessment ───"));

  const riskColor = m.riskScore >= 80 ? chalk.red.bold : m.riskScore >= 60 ? chalk.red : m.riskScore >= 30 ? chalk.yellow : chalk.green;
  console.log(chalk.white.bold("  Risk Score:   ") + riskColor(`${m.riskScore}/100 (${m.riskLevel})`));

  if (m.kevCount > 0) {
    console.log(chalk.red.bold(`  KEV (Exploited): ${m.kevCount} `) + chalk.gray(`(${m.kevWithFix} fixable)`));
  }

  if (m.highEpssCount > 0) {
    console.log(chalk.yellow(`  High EPSS:    ${m.highEpssCount} vulns with >50% exploit probability`));
  }

  if (m.criticalWithFix > 0 || m.highWithFix > 0) {
    console.log(
      chalk.green(`  Quick wins:   ${m.criticalWithFix} critical + ${m.highWithFix} high have fixes available`)
    );
  }

  console.log(
    chalk.gray(`  Deps: ${m.directDependencies} direct, ${m.transitiveDependencies} transitive`) +
    (m.copyleftCount > 0 ? chalk.yellow(` | ${m.copyleftCount} copyleft`) : "")
  );
}

function printKEVWarnings(report: ScanReport): void {
  const kevVulns: Array<{ vuln: any; pkg: string }> = [];

  for (const result of report.results) {
    for (const vuln of result.vulnerabilities) {
      if (vuln.isKnownExploited) {
        kevVulns.push({
          vuln,
          pkg: `${result.dependency.name}@${result.dependency.version}`,
        });
      }
    }
  }

  if (kevVulns.length > 0) {
    console.log(chalk.bgRed.white.bold("  ⚠ KNOWN EXPLOITED VULNERABILITIES (CISA KEV) "));
    console.log();
    for (const { vuln, pkg } of kevVulns) {
      console.log(
        chalk.red.bold(`  🔥 ${vuln.id}`) +
        chalk.gray(` in `) +
        chalk.white(pkg)
      );
      if (vuln.kevDueDate) {
        console.log(chalk.red(`     Remediation due: ${vuln.kevDueDate}`));
      }
      if (vuln.fixed_version) {
        console.log(chalk.green(`     Fix: upgrade to ${vuln.fixed_version}`));
      }
    }
    console.log();
  }
}

function printVulnerablePackage(result: ScanResult): void {
  const dep = result.dependency;
  const label = dep.isDirect ? chalk.cyan("[direct]") : chalk.gray("[transitive]");

  console.log(
    chalk.white.bold(`  ┌─ ${dep.name}@${dep.version}`) +
    ` ${label} ` +
    chalk.gray(`(${dep.ecosystem})`)
  );

  for (const vuln of result.vulnerabilities) {
    const sevColor = SEVERITY_COLORS[vuln.severity];
    const kevBadge = vuln.isKnownExploited ? chalk.red(" KEV") : "";

    console.log(
      chalk.gray("  │ ") +
      sevColor(`[${vuln.severity}]`) +
      kevBadge +
      " " +
      chalk.white(vuln.id)
    );
    console.log(chalk.gray("  │   ") + chalk.gray(truncate(vuln.summary, 70)));

    if (vuln.fixed_version) {
      console.log(
        chalk.gray("  │   ") +
        chalk.green(`Fix: upgrade to ${vuln.fixed_version}`)
      );
    }

    const meta: string[] = [];
    if (vuln.score) meta.push(`CVSS: ${vuln.score}`);
    if (vuln.epssScore) meta.push(`EPSS: ${(vuln.epssScore * 100).toFixed(1)}%`);
    if (vuln.cwes?.length) meta.push(vuln.cwes.slice(0, 2).join(", "));

    if (meta.length > 0) {
      console.log(chalk.gray("  │   ") + chalk.gray(meta.join(" | ")));
    }
  }

  console.log(chalk.gray("  └─"));
  console.log();
}

async function printLicenseSummary(report: ScanReport): Promise<void> {
  try {
    const { detectLicense } = await import("../../enrichment/license/detector.js");
    const copyleftDeps: Array<{ name: string; version: string; license: string }> = [];

    for (const result of report.results) {
      const dep = result.dependency;
      if (dep.license) {
        const info = detectLicense(dep.license);
        if (info?.isCopyleft) {
          copyleftDeps.push({
            name: dep.name,
            version: dep.version,
            license: info.name,
          });
        }
      }
    }

    if (copyleftDeps.length > 0) {
      console.log();
      console.log(chalk.yellow.bold("  ⚠ Copyleft License Warnings:"));
      for (const dep of copyleftDeps) {
        console.log(
          chalk.yellow(`    ${dep.name}@${dep.version}`) +
          chalk.gray(` — ${dep.license}`)
        );
      }
    }
  } catch {
    // License detection unavailable, skip
  }
}

function printPolicyResults(report: ScanReport): void {
  const policy = report.policyResult!;

  console.log();
  if (policy.passed) {
    console.log(chalk.green.bold("  ✓ Policy: PASSED"));
  } else {
    console.log(chalk.red.bold("  ✗ Policy: FAILED"));
    for (const v of policy.violations) {
      console.log(chalk.red(`    ✗ ${v.ruleName}: ${v.message}`));
    }
  }

  if (policy.warnings.length > 0) {
    for (const w of policy.warnings) {
      console.log(chalk.yellow(`    ⚠ ${w.ruleName}: ${w.message}`));
    }
  }
}

function truncate(str: string, max: number): string {
  return str.length > max ? str.slice(0, max - 3) + "..." : str;
}
