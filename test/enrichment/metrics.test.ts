// ─── Metrics Calculator Tests ───
// Tests risk score calculation and analytics computation

import { describe, test, expect } from "bun:test";
import { calculateMetrics } from "../../src/enrichment/metrics/calculator.js";
import type { ScanReport, ScanResult, Vulnerability, Severity } from "../../src/types.js";

// ═══════════════════════════════════════════
// Mock Data Factory
// ═══════════════════════════════════════════

function createVuln(overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id: "CVE-2024-0001",
    aliases: [],
    summary: "Test vulnerability",
    details: "Test vulnerability details",
    severity: "MEDIUM",
    affected_versions: ">=1.0.0",
    references: [],
    published: "2024-06-01T00:00:00Z",
    source: "osv",
    ...overrides,
  };
}

function createResult(overrides: {
  name?: string;
  version?: string;
  isDirect?: boolean;
  license?: string;
  vulns?: Partial<Vulnerability>[];
} = {}): ScanResult {
  const vulns = (overrides.vulns || []).map((v, i) =>
    createVuln({ id: `CVE-2024-${String(i + 1).padStart(4, "0")}`, ...v })
  );
  return {
    dependency: {
      name: overrides.name || "test-pkg",
      version: overrides.version || "1.0.0",
      ecosystem: "npm",
      isDirect: overrides.isDirect ?? true,
      license: overrides.license,
    },
    vulnerabilities: vulns,
  };
}

function createReport(results: ScanResult[], overrides: Partial<ScanReport> = {}): ScanReport {
  const allVulns = results.flatMap((r) => r.vulnerabilities);
  const severityCounts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    UNKNOWN: 0,
  };
  for (const v of allVulns) {
    severityCounts[v.severity]++;
  }

  return {
    tool: "scato",
    version: "3.0.0",
    timestamp: new Date().toISOString(),
    target: "/test",
    ecosystems: ["npm"],
    totalDependencies: results.length,
    totalVulnerabilities: allVulns.length,
    severityCounts,
    results,
    ...overrides,
  };
}

// ═══════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════

describe("calculateMetrics", () => {
  describe("risk score", () => {
    test("returns 0 for no vulnerabilities", () => {
      const report = createReport([
        createResult({ name: "safe-pkg" }),
      ]);

      const metrics = calculateMetrics(report);
      expect(metrics.riskScore).toBe(0);
      expect(metrics.riskLevel).toBe("none");
    });

    test("scores higher for CRITICAL than LOW", () => {
      const criticalReport = createReport([
        createResult({
          name: "critical-pkg",
          vulns: [{ severity: "CRITICAL", score: 9.8 }],
        }),
      ]);

      const lowReport = createReport([
        createResult({
          name: "low-pkg",
          vulns: [{ severity: "LOW", score: 2.0 }],
        }),
      ]);

      const criticalMetrics = calculateMetrics(criticalReport);
      const lowMetrics = calculateMetrics(lowReport);

      expect(criticalMetrics.riskScore).toBeGreaterThan(lowMetrics.riskScore);
    });

    test("scores higher for HIGH than MEDIUM", () => {
      const highReport = createReport([
        createResult({
          name: "high-pkg",
          vulns: [{ severity: "HIGH", score: 8.0 }],
        }),
      ]);

      const mediumReport = createReport([
        createResult({
          name: "medium-pkg",
          vulns: [{ severity: "MEDIUM", score: 5.0 }],
        }),
      ]);

      const highMetrics = calculateMetrics(highReport);
      const mediumMetrics = calculateMetrics(mediumReport);

      expect(highMetrics.riskScore).toBeGreaterThan(mediumMetrics.riskScore);
    });

    test("multiple vulnerabilities increase score", () => {
      const singleReport = createReport([
        createResult({
          name: "single-vuln",
          vulns: [{ severity: "HIGH" }],
        }),
      ]);

      const multiReport = createReport([
        createResult({
          name: "multi-vuln",
          vulns: [
            { severity: "HIGH" },
            { severity: "HIGH" },
            { severity: "HIGH" },
          ],
        }),
      ]);

      const singleMetrics = calculateMetrics(singleReport);
      const multiMetrics = calculateMetrics(multiReport);

      expect(multiMetrics.riskScore).toBeGreaterThan(singleMetrics.riskScore);
    });

    test("risk score is capped at 100", () => {
      const extremeReport = createReport([
        createResult({
          name: "extreme-pkg",
          vulns: Array.from({ length: 50 }, (_, i) => ({
            severity: "CRITICAL" as Severity,
            score: 10.0,
            isKnownExploited: true,
            epssScore: 0.99,
          })),
        }),
      ]);

      const metrics = calculateMetrics(extremeReport);
      expect(metrics.riskScore).toBeLessThanOrEqual(100);
    });
  });

  describe("KEV multiplier", () => {
    test("KEV multiplier increases score", () => {
      const nonKevReport = createReport([
        createResult({
          name: "non-kev",
          vulns: [{ severity: "CRITICAL", isKnownExploited: false }],
        }),
      ]);

      const kevReport = createReport([
        createResult({
          name: "kev-pkg",
          vulns: [{ severity: "CRITICAL", isKnownExploited: true }],
        }),
      ]);

      const nonKevMetrics = calculateMetrics(nonKevReport);
      const kevMetrics = calculateMetrics(kevReport);

      expect(kevMetrics.riskScore).toBeGreaterThan(nonKevMetrics.riskScore);
    });

    test("counts KEV vulnerabilities correctly", () => {
      const report = createReport([
        createResult({
          name: "kev-pkg-1",
          vulns: [
            { severity: "CRITICAL", isKnownExploited: true },
            { severity: "HIGH", isKnownExploited: true },
          ],
        }),
        createResult({
          name: "kev-pkg-2",
          vulns: [
            { severity: "MEDIUM", isKnownExploited: false },
          ],
        }),
      ]);

      const metrics = calculateMetrics(report);
      expect(metrics.kevCount).toBe(2);
    });

    test("counts KEV with fix available", () => {
      const report = createReport([
        createResult({
          name: "kev-fixable",
          vulns: [
            { severity: "CRITICAL", isKnownExploited: true, fixed_version: "2.0.0" },
            { severity: "HIGH", isKnownExploited: true },
          ],
        }),
      ]);

      const metrics = calculateMetrics(report);
      expect(metrics.kevWithFix).toBe(1);
    });
  });

  describe("EPSS metrics", () => {
    test("EPSS > 0.5 increases score", () => {
      const lowEpssReport = createReport([
        createResult({
          name: "low-epss",
          vulns: [{ severity: "HIGH", epssScore: 0.1 }],
        }),
      ]);

      const highEpssReport = createReport([
        createResult({
          name: "high-epss",
          vulns: [{ severity: "HIGH", epssScore: 0.8 }],
        }),
      ]);

      const lowEpssMetrics = calculateMetrics(lowEpssReport);
      const highEpssMetrics = calculateMetrics(highEpssReport);

      expect(highEpssMetrics.riskScore).toBeGreaterThan(lowEpssMetrics.riskScore);
    });

    test("calculates average EPSS score", () => {
      const report = createReport([
        createResult({
          name: "epss-pkg",
          vulns: [
            { severity: "HIGH", epssScore: 0.3 },
            { severity: "MEDIUM", epssScore: 0.7 },
          ],
        }),
      ]);

      const metrics = calculateMetrics(report);
      expect(metrics.avgEpssScore).toBeCloseTo(0.5, 1);
    });

    test("calculates max EPSS score", () => {
      const report = createReport([
        createResult({
          name: "epss-pkg",
          vulns: [
            { severity: "HIGH", epssScore: 0.3 },
            { severity: "MEDIUM", epssScore: 0.85 },
            { severity: "LOW", epssScore: 0.1 },
          ],
        }),
      ]);

      const metrics = calculateMetrics(report);
      expect(metrics.maxEpssScore).toBeCloseTo(0.85, 2);
    });

    test("counts high EPSS vulnerabilities (>0.5)", () => {
      const report = createReport([
        createResult({
          name: "epss-pkg",
          vulns: [
            { severity: "HIGH", epssScore: 0.3 },
            { severity: "MEDIUM", epssScore: 0.85 },
            { severity: "LOW", epssScore: 0.6 },
            { severity: "LOW", epssScore: 0.1 },
          ],
        }),
      ]);

      const metrics = calculateMetrics(report);
      expect(metrics.highEpssCount).toBe(2);
    });

    test("handles vulns without EPSS scores", () => {
      const report = createReport([
        createResult({
          name: "no-epss",
          vulns: [{ severity: "HIGH" }],
        }),
      ]);

      const metrics = calculateMetrics(report);
      expect(metrics.avgEpssScore).toBe(0);
      expect(metrics.maxEpssScore).toBe(0);
      expect(metrics.highEpssCount).toBe(0);
    });
  });

  describe("fix availability", () => {
    test("counts critical vulnerabilities with fixes", () => {
      const report = createReport([
        createResult({
          name: "fixable-critical",
          vulns: [
            { severity: "CRITICAL", fixed_version: "2.0.0" },
            { severity: "CRITICAL" },
            { severity: "CRITICAL", fixed_version: "3.0.0" },
          ],
        }),
      ]);

      const metrics = calculateMetrics(report);
      expect(metrics.criticalWithFix).toBe(2);
    });

    test("counts high vulnerabilities with fixes", () => {
      const report = createReport([
        createResult({
          name: "fixable-high",
          vulns: [
            { severity: "HIGH", fixed_version: "1.5.0" },
            { severity: "HIGH" },
          ],
        }),
      ]);

      const metrics = calculateMetrics(report);
      expect(metrics.highWithFix).toBe(1);
    });
  });

  describe("license metrics", () => {
    test("counts copyleft licenses correctly", () => {
      const report = createReport([
        createResult({ name: "gpl-pkg", license: "GPL-3.0" }),
        createResult({ name: "mit-pkg", license: "MIT" }),
        createResult({ name: "agpl-pkg", license: "AGPL-3.0" }),
        createResult({ name: "apache-pkg", license: "Apache-2.0" }),
      ]);

      const metrics = calculateMetrics(report);
      expect(metrics.copyleftCount).toBe(2);
    });

    test("counts unknown licenses", () => {
      const report = createReport([
        createResult({ name: "no-license-1" }), // no license
        createResult({ name: "no-license-2" }), // no license
        createResult({ name: "mit-pkg", license: "MIT" }),
      ]);

      const metrics = calculateMetrics(report);
      expect(metrics.unknownLicenseCount).toBe(2);
    });

    test("counts unique licenses", () => {
      const report = createReport([
        createResult({ name: "pkg-1", license: "MIT" }),
        createResult({ name: "pkg-2", license: "MIT" }),
        createResult({ name: "pkg-3", license: "Apache-2.0" }),
        createResult({ name: "pkg-4", license: "ISC" }),
      ]);

      const metrics = calculateMetrics(report);
      expect(metrics.uniqueLicenses).toBe(3);
    });
  });

  describe("dependency metrics", () => {
    test("counts direct and transitive dependencies", () => {
      const report = createReport([
        createResult({ name: "direct-1", isDirect: true }),
        createResult({ name: "direct-2", isDirect: true }),
        createResult({ name: "transitive-1", isDirect: false }),
        createResult({ name: "transitive-2", isDirect: false }),
        createResult({ name: "transitive-3", isDirect: false }),
      ]);

      const metrics = calculateMetrics(report);
      expect(metrics.directDependencies).toBe(2);
      expect(metrics.transitiveDependencies).toBe(3);
    });

    test("max depth defaults to 0 without dependency trees", () => {
      const report = createReport([
        createResult({ name: "pkg-1" }),
      ]);

      const metrics = calculateMetrics(report);
      expect(metrics.maxDepth).toBe(0);
    });

    test("uses dependency tree max depth when available", () => {
      const report = createReport([
        createResult({ name: "pkg-1" }),
      ]);
      report.dependencyTrees = [
        {
          root: "pkg-1",
          ecosystem: "npm",
          nodes: [],
          totalCount: 10,
          directCount: 3,
          transitiveCount: 7,
          maxDepth: 5,
        },
      ];

      const metrics = calculateMetrics(report);
      expect(metrics.maxDepth).toBe(5);
    });
  });

  describe("risk levels", () => {
    test("risk level is 'none' for score 0", () => {
      const report = createReport([createResult()]);
      const metrics = calculateMetrics(report);
      expect(metrics.riskLevel).toBe("none");
    });

    test("risk level is 'low' for low scores", () => {
      const report = createReport([
        createResult({
          vulns: [{ severity: "LOW", score: 2.0 }],
        }),
      ]);
      const metrics = calculateMetrics(report);
      expect(metrics.riskScore).toBeGreaterThan(0);
      expect(metrics.riskScore).toBeLessThan(30);
      expect(metrics.riskLevel).toBe("low");
    });

    test("risk level is 'critical' for very high scores", () => {
      const report = createReport([
        createResult({
          vulns: Array.from({ length: 20 }, () => ({
            severity: "CRITICAL" as Severity,
            score: 10.0,
            isKnownExploited: true,
            epssScore: 0.95,
          })),
        }),
      ]);
      const metrics = calculateMetrics(report);
      expect(metrics.riskLevel).toBe("critical");
    });
  });

  describe("vulnerability age", () => {
    test("calculates median vulnerability age", () => {
      const now = Date.now();
      const thirtyDaysAgo = new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString();
      const sixtyDaysAgo = new Date(now - 60 * 24 * 60 * 60 * 1000).toISOString();
      const ninetyDaysAgo = new Date(now - 90 * 24 * 60 * 60 * 1000).toISOString();

      const report = createReport([
        createResult({
          vulns: [
            { severity: "HIGH", published: thirtyDaysAgo },
            { severity: "MEDIUM", published: sixtyDaysAgo },
            { severity: "LOW", published: ninetyDaysAgo },
          ],
        }),
      ]);

      const metrics = calculateMetrics(report);
      // Median of [30, 60, 90] = 60
      expect(metrics.medianVulnAge).toBeGreaterThanOrEqual(58);
      expect(metrics.medianVulnAge).toBeLessThanOrEqual(62);
    });

    test("tracks oldest unfixed vulnerability", () => {
      const now = Date.now();
      const oldDate = new Date(now - 365 * 24 * 60 * 60 * 1000).toISOString();
      const recentDate = new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString();

      const report = createReport([
        createResult({
          vulns: [
            { id: "CVE-OLD", severity: "HIGH", published: oldDate },
            { id: "CVE-RECENT", severity: "MEDIUM", published: recentDate, fixed_version: "2.0.0" },
          ],
        }),
      ]);

      const metrics = calculateMetrics(report);
      expect(metrics.oldestUnfixedVuln).toBeDefined();
      expect(metrics.oldestUnfixedVuln!.id).toBe("CVE-OLD");
      expect(metrics.oldestUnfixedVuln!.age).toBeGreaterThanOrEqual(363);
    });
  });
});
