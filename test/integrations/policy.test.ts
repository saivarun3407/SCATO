// ─── Policy Engine Tests ───
// Tests policy evaluation against scan results

import { describe, test, expect } from "bun:test";
import {
  evaluatePolicy,
  loadPolicy,
  DEFAULT_POLICY,
} from "../../src/integrations/policy/engine.js";
import type {
  ScanReport,
  ScanResult,
  PolicyRule,
  Severity,
  Vulnerability,
} from "../../src/types.js";

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

function createCleanReport(): ScanReport {
  return {
    tool: "scato",
    version: "3.0.0",
    timestamp: new Date().toISOString(),
    target: "/test/clean-project",
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
        },
        vulnerabilities: [],
      },
    ],
    metrics: {
      riskScore: 0,
      riskLevel: "none",
      criticalWithFix: 0,
      highWithFix: 0,
      medianVulnAge: 0,
      kevCount: 0,
      kevWithFix: 0,
      avgEpssScore: 0,
      maxEpssScore: 0,
      highEpssCount: 0,
      copyleftCount: 0,
      unknownLicenseCount: 0,
      uniqueLicenses: 2,
      directDependencies: 2,
      transitiveDependencies: 0,
      maxDepth: 0,
      outdatedCount: 0,
    },
  };
}

function createVulnerableReport(vulnOverrides: Partial<Vulnerability>[] = []): ScanReport {
  const vulns = vulnOverrides.length > 0
    ? vulnOverrides.map((v, i) => createVuln({ id: `CVE-2024-${String(i + 1).padStart(4, "0")}`, ...v }))
    : [createVuln({ id: "CVE-2024-0001", severity: "CRITICAL", score: 9.8 })];

  const severityCounts: Record<Severity, number> = {
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0,
  };
  for (const v of vulns) {
    severityCounts[v.severity]++;
  }

  return {
    tool: "scato",
    version: "3.0.0",
    timestamp: new Date().toISOString(),
    target: "/test/vulnerable-project",
    ecosystems: ["npm"],
    totalDependencies: 1,
    totalVulnerabilities: vulns.length,
    severityCounts,
    results: [
      {
        dependency: {
          name: "vulnerable-pkg",
          version: "1.0.0",
          ecosystem: "npm",
          isDirect: true,
          license: "MIT",
        },
        vulnerabilities: vulns,
      },
    ],
    metrics: {
      riskScore: 50,
      riskLevel: "medium",
      criticalWithFix: 0,
      highWithFix: 0,
      medianVulnAge: 30,
      kevCount: vulns.filter((v) => v.isKnownExploited).length,
      kevWithFix: 0,
      avgEpssScore: 0,
      maxEpssScore: 0,
      highEpssCount: 0,
      copyleftCount: 0,
      unknownLicenseCount: 0,
      uniqueLicenses: 1,
      directDependencies: 1,
      transitiveDependencies: 0,
      maxDepth: 0,
      outdatedCount: 0,
    },
  };
}

// ═══════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════

describe("evaluatePolicy", () => {
  describe("default policy with clean report", () => {
    test("passes for a clean report with no vulnerabilities", () => {
      const report = createCleanReport();
      const result = evaluatePolicy(report, DEFAULT_POLICY);

      expect(result.passed).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    test("returns empty warnings for clean report", () => {
      const report = createCleanReport();
      const result = evaluatePolicy(report, DEFAULT_POLICY);

      expect(result.warnings).toHaveLength(0);
    });
  });

  describe("max_severity rule", () => {
    test("fails when CRITICAL vuln exists and max is HIGH", () => {
      const report = createVulnerableReport([
        { severity: "CRITICAL", score: 9.8 },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "no-critical",
          name: "No Critical Vulnerabilities",
          description: "Block on critical severity",
          severity: "error",
          condition: { type: "max_severity", value: "HIGH" },
        },
      ];

      const result = evaluatePolicy(report, rules);

      expect(result.passed).toBe(false);
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].ruleId).toBe("no-critical");
      expect(result.violations[0].message).toContain("CRITICAL");
    });

    test("passes when only HIGH vulns and max is HIGH", () => {
      const report = createVulnerableReport([
        { severity: "HIGH", score: 7.5 },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "no-critical",
          name: "No Critical Vulnerabilities",
          description: "Block on critical severity",
          severity: "error",
          condition: { type: "max_severity", value: "HIGH" },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(true);
    });

    test("fails when HIGH vuln and max allowed is MEDIUM", () => {
      const report = createVulnerableReport([
        { severity: "HIGH", score: 7.0 },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "strict-severity",
          name: "Maximum Medium Severity",
          description: "Block on high or above",
          severity: "error",
          condition: { type: "max_severity", value: "MEDIUM" },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(false);
    });

    test("passes when MEDIUM vuln and max is MEDIUM", () => {
      const report = createVulnerableReport([
        { severity: "MEDIUM", score: 5.0 },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "allow-medium",
          name: "Allow Medium",
          description: "Block on high or above",
          severity: "error",
          condition: { type: "max_severity", value: "MEDIUM" },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(true);
    });

    test("includes dependency info in violation", () => {
      const report = createVulnerableReport([
        { severity: "CRITICAL" },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "no-critical",
          name: "No Critical",
          description: "Block critical",
          severity: "error",
          condition: { type: "max_severity", value: "HIGH" },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.violations[0].dependency).toBe("vulnerable-pkg@1.0.0");
      expect(result.violations[0].vulnerability).toBeDefined();
    });
  });

  describe("max_cvss rule", () => {
    test("fails when CVSS exceeds threshold", () => {
      const report = createVulnerableReport([
        { severity: "CRITICAL", score: 9.8 },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "max-cvss",
          name: "Max CVSS 7.0",
          description: "Block on CVSS > 7.0",
          severity: "error",
          condition: { type: "max_cvss", value: 7.0 },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(false);
      expect(result.violations[0].message).toContain("9.8");
    });

    test("passes when CVSS is below threshold", () => {
      const report = createVulnerableReport([
        { severity: "MEDIUM", score: 5.5 },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "max-cvss",
          name: "Max CVSS 7.0",
          description: "Block on CVSS > 7.0",
          severity: "error",
          condition: { type: "max_cvss", value: 7.0 },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(true);
    });
  });

  describe("no_kev rule", () => {
    test("fails when KEV vulnerability present", () => {
      const report = createVulnerableReport([
        {
          severity: "CRITICAL",
          isKnownExploited: true,
          kevDateAdded: "2024-01-15",
        },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "no-kev",
          name: "No KEV",
          description: "Block on known exploited vulns",
          severity: "error",
          condition: { type: "no_kev" },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(false);
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].message).toContain("KEV");
    });

    test("passes when no KEV vulnerabilities present", () => {
      const report = createVulnerableReport([
        { severity: "CRITICAL", isKnownExploited: false },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "no-kev",
          name: "No KEV",
          description: "Block on known exploited vulns",
          severity: "error",
          condition: { type: "no_kev" },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(true);
    });

    test("detects multiple KEV vulnerabilities", () => {
      const report = createVulnerableReport([
        { severity: "CRITICAL", isKnownExploited: true },
        { severity: "HIGH", isKnownExploited: true },
        { severity: "MEDIUM", isKnownExploited: false },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "no-kev",
          name: "No KEV",
          description: "Block on known exploited vulns",
          severity: "error",
          condition: { type: "no_kev" },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.violations).toHaveLength(2);
    });
  });

  describe("max_epss rule", () => {
    test("fails when EPSS exceeds threshold", () => {
      const report = createVulnerableReport([
        { severity: "HIGH", epssScore: 0.85 },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "epss-check",
          name: "EPSS Below 70%",
          description: "Block on high EPSS",
          severity: "error",
          condition: { type: "max_epss", value: 0.7 },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(false);
      expect(result.violations[0].message).toContain("85.0%");
    });

    test("passes when EPSS is below threshold", () => {
      const report = createVulnerableReport([
        { severity: "HIGH", epssScore: 0.3 },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "epss-check",
          name: "EPSS Below 70%",
          description: "Block on high EPSS",
          severity: "error",
          condition: { type: "max_epss", value: 0.7 },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(true);
    });
  });

  describe("no_copyleft rule", () => {
    test("fails when copyleft dependencies exist", () => {
      const report = createCleanReport();
      report.metrics!.copyleftCount = 3;

      const rules: PolicyRule[] = [
        {
          id: "no-copyleft",
          name: "No Copyleft",
          description: "Block on copyleft licenses",
          severity: "error",
          condition: { type: "no_copyleft" },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(false);
      expect(result.violations[0].message).toContain("3");
    });

    test("passes when no copyleft dependencies", () => {
      const report = createCleanReport();
      report.metrics!.copyleftCount = 0;

      const rules: PolicyRule[] = [
        {
          id: "no-copyleft",
          name: "No Copyleft",
          description: "Block on copyleft licenses",
          severity: "error",
          condition: { type: "no_copyleft" },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(true);
    });
  });

  describe("no_unknown_license rule", () => {
    test("fails when unknown licenses exist", () => {
      const report = createCleanReport();
      report.metrics!.unknownLicenseCount = 5;

      const rules: PolicyRule[] = [
        {
          id: "no-unknown",
          name: "No Unknown License",
          description: "Block on unknown licenses",
          severity: "error",
          condition: { type: "no_unknown_license" },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(false);
      expect(result.violations[0].message).toContain("5");
    });
  });

  describe("max_vuln_age rule", () => {
    test("fails when unfixed vuln exceeds age threshold", () => {
      const oldDate = new Date(Date.now() - 120 * 24 * 60 * 60 * 1000).toISOString();
      const report = createVulnerableReport([
        { severity: "HIGH", published: oldDate },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "max-age",
          name: "Max Vuln Age 90 Days",
          description: "Block on old unfixed vulns",
          severity: "error",
          condition: { type: "max_vuln_age", days: 90 },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(false);
      expect(result.violations[0].message).toContain("days");
    });

    test("passes when unfixed vuln is within age threshold", () => {
      const recentDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
      const report = createVulnerableReport([
        { severity: "HIGH", published: recentDate },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "max-age",
          name: "Max Vuln Age 90 Days",
          description: "Block on old unfixed vulns",
          severity: "error",
          condition: { type: "max_vuln_age", days: 90 },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(true);
    });

    test("passes when old vuln has a fix available", () => {
      const oldDate = new Date(Date.now() - 120 * 24 * 60 * 60 * 1000).toISOString();
      const report = createVulnerableReport([
        { severity: "HIGH", published: oldDate, fixed_version: "2.0.0" },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "max-age",
          name: "Max Vuln Age 90 Days",
          description: "Block on old unfixed vulns",
          severity: "error",
          condition: { type: "max_vuln_age", days: 90 },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(true);
    });
  });

  describe("warnings vs errors distinction", () => {
    test("warning-severity rules go to warnings, not violations", () => {
      const report = createVulnerableReport([
        { severity: "HIGH", epssScore: 0.85 },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "epss-warn",
          name: "EPSS Warning",
          description: "Warn on high EPSS",
          severity: "warning",
          condition: { type: "max_epss", value: 0.7 },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(true); // warnings don't cause failure
      expect(result.violations).toHaveLength(0);
      expect(result.warnings).toHaveLength(1);
    });

    test("error-severity rules cause failure", () => {
      const report = createVulnerableReport([
        { severity: "HIGH", epssScore: 0.85 },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "epss-error",
          name: "EPSS Error",
          description: "Block on high EPSS",
          severity: "error",
          condition: { type: "max_epss", value: 0.7 },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(false);
      expect(result.violations).toHaveLength(1);
      expect(result.warnings).toHaveLength(0);
    });

    test("mixed error and warning rules are separated correctly", () => {
      const report = createVulnerableReport([
        { severity: "CRITICAL", score: 9.8, epssScore: 0.85 },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "severity-error",
          name: "No Critical",
          description: "Block critical",
          severity: "error",
          condition: { type: "max_severity", value: "HIGH" },
        },
        {
          id: "epss-warn",
          name: "EPSS Warning",
          description: "Warn on high EPSS",
          severity: "warning",
          condition: { type: "max_epss", value: 0.7 },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(false);
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].ruleId).toBe("severity-error");
      expect(result.warnings).toHaveLength(1);
      expect(result.warnings[0].ruleId).toBe("epss-warn");
    });
  });

  describe("multiple rules evaluation", () => {
    test("evaluates all rules and collects all violations", () => {
      const report = createVulnerableReport([
        {
          severity: "CRITICAL",
          score: 9.8,
          isKnownExploited: true,
        },
      ]);

      const rules: PolicyRule[] = [
        {
          id: "no-critical",
          name: "No Critical",
          description: "Block critical",
          severity: "error",
          condition: { type: "max_severity", value: "HIGH" },
        },
        {
          id: "no-kev",
          name: "No KEV",
          description: "Block KEV",
          severity: "error",
          condition: { type: "no_kev" },
        },
        {
          id: "max-cvss",
          name: "Max CVSS 7.0",
          description: "Block high CVSS",
          severity: "error",
          condition: { type: "max_cvss", value: 7.0 },
        },
      ];

      const result = evaluatePolicy(report, rules);
      expect(result.passed).toBe(false);
      expect(result.violations).toHaveLength(3);
    });

    test("empty rules array always passes", () => {
      const report = createVulnerableReport([
        { severity: "CRITICAL" },
      ]);

      const result = evaluatePolicy(report, []);
      expect(result.passed).toBe(true);
      expect(result.violations).toHaveLength(0);
    });
  });
});

describe("loadPolicy", () => {
  test("returns default policy when no file specified", async () => {
    const policy = await loadPolicy();
    expect(policy).toBe(DEFAULT_POLICY);
    expect(policy.length).toBeGreaterThan(0);
  });

  test("returns default policy when file does not exist", async () => {
    const policy = await loadPolicy("/nonexistent/policy.json");
    expect(policy).toBe(DEFAULT_POLICY);
  });

  test("default policy includes no-critical rule", () => {
    const noCriticalRule = DEFAULT_POLICY.find((r) => r.id === "no-critical");
    expect(noCriticalRule).toBeDefined();
    expect(noCriticalRule!.severity).toBe("error");
    expect(noCriticalRule!.condition.type).toBe("max_severity");
  });

  test("default policy includes no-kev rule", () => {
    const noKevRule = DEFAULT_POLICY.find((r) => r.id === "no-kev");
    expect(noKevRule).toBeDefined();
    expect(noKevRule!.severity).toBe("error");
    expect(noKevRule!.condition.type).toBe("no_kev");
  });

  test("default policy includes epss-threshold as warning", () => {
    const epssRule = DEFAULT_POLICY.find((r) => r.id === "epss-threshold");
    expect(epssRule).toBeDefined();
    expect(epssRule!.severity).toBe("warning");
  });

  test("default policy includes copyleft-check as warning", () => {
    const copyleftRule = DEFAULT_POLICY.find((r) => r.id === "copyleft-check");
    expect(copyleftRule).toBeDefined();
    expect(copyleftRule!.severity).toBe("warning");
  });
});
