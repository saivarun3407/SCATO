// ─── Output Formatters Tests ───
// Tests JSON output and terminal report generation with mock ScanReport data

import { describe, test, expect, mock, beforeEach, afterEach } from "bun:test";
import { formatJsonReport } from "../../../src/core/output/json.js";
import { printReport } from "../../../src/core/output/terminal.js";
import type { ScanReport, Severity } from "../../../src/types.js";

// ═══════════════════════════════════════════
// Mock Data Factory
// ═══════════════════════════════════════════

function createMockReport(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    tool: "scato",
    version: "3.0.0",
    timestamp: "2026-02-07T12:00:00.000Z",
    target: "/projects/test-app",
    ecosystems: ["npm"],
    totalDependencies: 3,
    totalVulnerabilities: 2,
    severityCounts: {
      CRITICAL: 1,
      HIGH: 1,
      MEDIUM: 0,
      LOW: 0,
      UNKNOWN: 0,
    },
    results: [
      {
        dependency: {
          name: "express",
          version: "4.17.1",
          ecosystem: "npm",
          isDirect: true,
          license: "MIT",
          purl: "pkg:npm/express@4.17.1",
        },
        vulnerabilities: [
          {
            id: "CVE-2024-1234",
            aliases: ["GHSA-abcd-efgh-ijkl"],
            summary: "Prototype pollution in express",
            details: "A prototype pollution vulnerability exists in express.",
            severity: "CRITICAL",
            score: 9.8,
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            affected_versions: ">=4.0.0, <4.18.0",
            fixed_version: "4.18.0",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
            published: "2024-01-15T00:00:00Z",
            source: "osv",
            isKnownExploited: true,
            kevDateAdded: "2024-02-01",
            kevDueDate: "2024-03-01",
            epssScore: 0.85,
            epssPercentile: 0.97,
            cwes: ["CWE-1321"],
          },
        ],
      },
      {
        dependency: {
          name: "lodash",
          version: "4.17.20",
          ecosystem: "npm",
          isDirect: true,
          license: "MIT",
          purl: "pkg:npm/lodash@4.17.20",
        },
        vulnerabilities: [
          {
            id: "CVE-2024-5678",
            aliases: [],
            summary: "ReDoS vulnerability in lodash",
            details: "Regular expression denial of service.",
            severity: "HIGH",
            score: 7.5,
            affected_versions: ">=4.0.0, <4.17.21",
            fixed_version: "4.17.21",
            references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-5678"],
            published: "2024-03-10T00:00:00Z",
            source: "osv",
            epssScore: 0.32,
          },
        ],
      },
      {
        dependency: {
          name: "debug",
          version: "4.3.4",
          ecosystem: "npm",
          isDirect: false,
          license: "MIT",
          parent: "express",
        },
        vulnerabilities: [],
      },
    ],
    scanDurationMs: 1523,
    scanId: "test-scan-001",
    dataSourceTimestamps: {
      osv: "2026-02-07T12:00:00.000Z",
      kev: "2026-02-07T12:00:00.000Z",
      epss: "2026-02-07T12:00:00.000Z",
    },
    metrics: {
      riskScore: 72,
      riskLevel: "high",
      criticalWithFix: 1,
      highWithFix: 1,
      medianVulnAge: 365,
      kevCount: 1,
      kevWithFix: 1,
      avgEpssScore: 0.585,
      maxEpssScore: 0.85,
      highEpssCount: 1,
      copyleftCount: 0,
      unknownLicenseCount: 0,
      uniqueLicenses: 1,
      directDependencies: 2,
      transitiveDependencies: 1,
      maxDepth: 1,
      outdatedCount: 0,
    },
    policyResult: {
      passed: false,
      violations: [
        {
          ruleId: "no-critical",
          ruleName: "No Critical Vulnerabilities",
          message: "CVE-2024-1234 has severity CRITICAL (max allowed: HIGH)",
          severity: "error",
          dependency: "express@4.17.1",
          vulnerability: "CVE-2024-1234",
        },
      ],
      warnings: [
        {
          ruleId: "epss-threshold",
          ruleName: "EPSS Score Below 70%",
          message: "CVE-2024-1234 has EPSS score 85.0% (max: 70%)",
          severity: "warning",
          dependency: "express@4.17.1",
          vulnerability: "CVE-2024-1234",
        },
      ],
    },
    ...overrides,
  };
}

function createCleanReport(): ScanReport {
  return {
    tool: "scato",
    version: "3.0.0",
    timestamp: "2026-02-07T12:00:00.000Z",
    target: "/projects/clean-app",
    ecosystems: ["npm"],
    totalDependencies: 2,
    totalVulnerabilities: 0,
    severityCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
    results: [
      {
        dependency: {
          name: "react",
          version: "18.2.0",
          ecosystem: "npm",
          isDirect: true,
          license: "MIT",
        },
        vulnerabilities: [],
      },
      {
        dependency: {
          name: "typescript",
          version: "5.6.0",
          ecosystem: "npm",
          isDirect: true,
          license: "Apache-2.0",
          scope: "dev",
        },
        vulnerabilities: [],
      },
    ],
    scanId: "test-clean-001",
  };
}

// ═══════════════════════════════════════════
// JSON Output Tests
// ═══════════════════════════════════════════

describe("formatJsonReport", () => {
  test("returns valid JSON string", () => {
    const report = createMockReport();
    const jsonStr = formatJsonReport(report);
    const parsed = JSON.parse(jsonStr);
    expect(parsed).toBeDefined();
  });

  test("preserves all report fields", () => {
    const report = createMockReport();
    const jsonStr = formatJsonReport(report);
    const parsed = JSON.parse(jsonStr) as ScanReport;

    expect(parsed.tool).toBe("scato");
    expect(parsed.version).toBe("3.0.0");
    expect(parsed.target).toBe("/projects/test-app");
    expect(parsed.ecosystems).toEqual(["npm"]);
    expect(parsed.totalDependencies).toBe(3);
    expect(parsed.totalVulnerabilities).toBe(2);
    expect(parsed.scanId).toBe("test-scan-001");
  });

  test("preserves severity counts", () => {
    const report = createMockReport();
    const parsed = JSON.parse(formatJsonReport(report)) as ScanReport;

    expect(parsed.severityCounts.CRITICAL).toBe(1);
    expect(parsed.severityCounts.HIGH).toBe(1);
    expect(parsed.severityCounts.MEDIUM).toBe(0);
    expect(parsed.severityCounts.LOW).toBe(0);
    expect(parsed.severityCounts.UNKNOWN).toBe(0);
  });

  test("preserves vulnerability details", () => {
    const report = createMockReport();
    const parsed = JSON.parse(formatJsonReport(report)) as ScanReport;

    const expressResult = parsed.results.find(
      (r) => r.dependency.name === "express"
    );
    expect(expressResult).toBeDefined();
    expect(expressResult!.vulnerabilities).toHaveLength(1);

    const vuln = expressResult!.vulnerabilities[0];
    expect(vuln.id).toBe("CVE-2024-1234");
    expect(vuln.severity).toBe("CRITICAL");
    expect(vuln.score).toBe(9.8);
    expect(vuln.isKnownExploited).toBe(true);
    expect(vuln.epssScore).toBe(0.85);
    expect(vuln.fixed_version).toBe("4.18.0");
  });

  test("preserves metrics in JSON output", () => {
    const report = createMockReport();
    const parsed = JSON.parse(formatJsonReport(report)) as ScanReport;

    expect(parsed.metrics).toBeDefined();
    expect(parsed.metrics!.riskScore).toBe(72);
    expect(parsed.metrics!.riskLevel).toBe("high");
    expect(parsed.metrics!.kevCount).toBe(1);
    expect(parsed.metrics!.highEpssCount).toBe(1);
  });

  test("preserves policy result in JSON output", () => {
    const report = createMockReport();
    const parsed = JSON.parse(formatJsonReport(report)) as ScanReport;

    expect(parsed.policyResult).toBeDefined();
    expect(parsed.policyResult!.passed).toBe(false);
    expect(parsed.policyResult!.violations).toHaveLength(1);
    expect(parsed.policyResult!.warnings).toHaveLength(1);
  });

  test("handles clean report with no vulnerabilities", () => {
    const report = createCleanReport();
    const jsonStr = formatJsonReport(report);
    const parsed = JSON.parse(jsonStr) as ScanReport;

    expect(parsed.totalVulnerabilities).toBe(0);
    expect(parsed.results.every((r) => r.vulnerabilities.length === 0)).toBe(true);
  });

  test("output is pretty-printed with 2-space indentation", () => {
    const report = createCleanReport();
    const jsonStr = formatJsonReport(report);

    // Pretty-printed JSON should contain newlines and 2-space indentation
    expect(jsonStr).toContain("\n");
    expect(jsonStr).toContain('  "tool"');
  });

  test("preserves data source timestamps", () => {
    const report = createMockReport();
    const parsed = JSON.parse(formatJsonReport(report)) as ScanReport;

    expect(parsed.dataSourceTimestamps).toBeDefined();
    expect(parsed.dataSourceTimestamps!.osv).toBeDefined();
    expect(parsed.dataSourceTimestamps!.kev).toBeDefined();
    expect(parsed.dataSourceTimestamps!.epss).toBeDefined();
  });
});

// ═══════════════════════════════════════════
// Terminal Reporter Tests
// ═══════════════════════════════════════════

describe("printReport", () => {
  let consoleLogSpy: ReturnType<typeof mock>;
  let logOutput: string[];

  beforeEach(() => {
    logOutput = [];
    consoleLogSpy = mock((...args: unknown[]) => {
      logOutput.push(args.map(String).join(" "));
    });
    // @ts-ignore - mocking console.log
    console.log = consoleLogSpy;
  });

  afterEach(() => {
    // Restore console.log is handled by bun:test isolation
  });

  test("prints SCATO header banner", async () => {
    const report = createMockReport();
    await printReport(report);

    const fullOutput = logOutput.join("\n");
    expect(fullOutput).toContain("SCATO");
  });

  test("prints target path", async () => {
    const report = createMockReport();
    await printReport(report);

    const fullOutput = logOutput.join("\n");
    expect(fullOutput).toContain("/projects/test-app");
  });

  test("prints dependency count", async () => {
    const report = createMockReport();
    await printReport(report);

    const fullOutput = logOutput.join("\n");
    expect(fullOutput).toContain("3");
  });

  test("prints no-vuln message for clean report", async () => {
    const report = createCleanReport();
    await printReport(report);

    const fullOutput = logOutput.join("\n");
    expect(fullOutput).toContain("No known vulnerabilities found");
  });

  test("prints vulnerability details for vulnerable report", async () => {
    const report = createMockReport();
    await printReport(report);

    const fullOutput = logOutput.join("\n");
    expect(fullOutput).toContain("CVE-2024-1234");
    expect(fullOutput).toContain("express");
    expect(fullOutput).toContain("CRITICAL");
  });

  test("prints KEV warnings when exploited vulns present", async () => {
    const report = createMockReport();
    await printReport(report);

    const fullOutput = logOutput.join("\n");
    expect(fullOutput).toContain("KEV");
    expect(fullOutput).toContain("CVE-2024-1234");
  });

  test("prints metrics block with risk score", async () => {
    const report = createMockReport();
    await printReport(report);

    const fullOutput = logOutput.join("\n");
    expect(fullOutput).toContain("Risk Score");
    expect(fullOutput).toContain("72");
  });

  test("prints policy FAILED when violations exist", async () => {
    const report = createMockReport();
    await printReport(report);

    const fullOutput = logOutput.join("\n");
    expect(fullOutput).toContain("FAILED");
  });

  test("prints policy PASSED for clean report with passing policy", async () => {
    const report = createCleanReport();
    report.policyResult = { passed: true, violations: [], warnings: [] };
    await printReport(report);

    const fullOutput = logOutput.join("\n");
    expect(fullOutput).toContain("PASSED");
  });

  test("prints scan duration when available", async () => {
    const report = createMockReport();
    await printReport(report);

    const fullOutput = logOutput.join("\n");
    expect(fullOutput).toContain("1.5");
  });

  test("prints data sources", async () => {
    const report = createMockReport();
    await printReport(report);

    const fullOutput = logOutput.join("\n");
    expect(fullOutput).toContain("OSV");
  });

  test("prints scan ID", async () => {
    const report = createMockReport();
    await printReport(report);

    const fullOutput = logOutput.join("\n");
    expect(fullOutput).toContain("test-scan-001");
  });

  test("prints SBOM path when present", async () => {
    const report = createMockReport({ sbomPath: "/output/sbom.json" });
    await printReport(report);

    const fullOutput = logOutput.join("\n");
    expect(fullOutput).toContain("/output/sbom.json");
  });

  test("prints fix suggestions", async () => {
    const report = createMockReport();
    await printReport(report);

    const fullOutput = logOutput.join("\n");
    expect(fullOutput).toContain("4.18.0");
  });
});
