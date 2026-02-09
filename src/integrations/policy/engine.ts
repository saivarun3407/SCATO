// ─── Policy Engine ───
// Evaluates scan results against configurable security policies

import { readFile } from "fs/promises";
import type {
  ScanReport,
  PolicyRule,
  PolicyResult,
  PolicyViolation,
  PolicyCondition,
  Severity,
} from "../../types.js";

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
};

// Default policy — strict but reasonable
export const DEFAULT_POLICY: PolicyRule[] = [
  {
    id: "no-critical",
    name: "No Critical Vulnerabilities",
    description: "Block on any critical severity vulnerability",
    severity: "error",
    condition: { type: "max_severity", value: "HIGH" },
  },
  {
    id: "no-kev",
    name: "No Known Exploited Vulnerabilities",
    description: "Block on any vulnerability in CISA KEV catalog",
    severity: "error",
    condition: { type: "no_kev" },
  },
  {
    id: "epss-threshold",
    name: "EPSS Score Below 70%",
    description: "Warn on vulnerabilities with high exploitation probability",
    severity: "warning",
    condition: { type: "max_epss", value: 0.7 },
  },
  {
    id: "copyleft-check",
    name: "No Copyleft Licenses",
    description: "Warn on copyleft-licensed dependencies",
    severity: "warning",
    condition: { type: "no_copyleft" },
  },
];

export async function loadPolicy(policyFile?: string): Promise<PolicyRule[]> {
  if (!policyFile) return DEFAULT_POLICY;

  try {
    const content = await readFile(policyFile, "utf-8");
    const parsed = JSON.parse(content) as { rules: PolicyRule[] };
    return parsed.rules || DEFAULT_POLICY;
  } catch {
    return DEFAULT_POLICY;
  }
}

export function evaluatePolicy(
  report: ScanReport,
  rules: PolicyRule[]
): PolicyResult {
  const violations: PolicyViolation[] = [];
  const warnings: PolicyViolation[] = [];

  for (const rule of rules) {
    const ruleViolations = evaluateRule(report, rule);

    for (const violation of ruleViolations) {
      if (rule.severity === "error") {
        violations.push(violation);
      } else {
        warnings.push(violation);
      }
    }
  }

  return {
    passed: violations.length === 0,
    violations,
    warnings,
  };
}

function evaluateRule(report: ScanReport, rule: PolicyRule): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  const cond = rule.condition;

  switch (cond.type) {
    case "max_severity": {
      const maxAllowed = SEVERITY_ORDER[cond.value];
      for (const result of report.results) {
        for (const vuln of result.vulnerabilities) {
          if (SEVERITY_ORDER[vuln.severity] > maxAllowed) {
            violations.push({
              ruleId: rule.id,
              ruleName: rule.name,
              message: `${vuln.id} has severity ${vuln.severity} (max allowed: ${cond.value})`,
              severity: rule.severity,
              dependency: `${result.dependency.name}@${result.dependency.version}`,
              vulnerability: vuln.id,
            });
          }
        }
      }
      break;
    }

    case "max_cvss": {
      for (const result of report.results) {
        for (const vuln of result.vulnerabilities) {
          if (vuln.score && vuln.score > cond.value) {
            violations.push({
              ruleId: rule.id,
              ruleName: rule.name,
              message: `${vuln.id} has CVSS ${vuln.score} (max allowed: ${cond.value})`,
              severity: rule.severity,
              dependency: `${result.dependency.name}@${result.dependency.version}`,
              vulnerability: vuln.id,
            });
          }
        }
      }
      break;
    }

    case "no_kev": {
      for (const result of report.results) {
        for (const vuln of result.vulnerabilities) {
          if (vuln.isKnownExploited) {
            violations.push({
              ruleId: rule.id,
              ruleName: rule.name,
              message: `${vuln.id} is in CISA KEV catalog (actively exploited)`,
              severity: rule.severity,
              dependency: `${result.dependency.name}@${result.dependency.version}`,
              vulnerability: vuln.id,
            });
          }
        }
      }
      break;
    }

    case "max_epss": {
      for (const result of report.results) {
        for (const vuln of result.vulnerabilities) {
          if (vuln.epssScore && vuln.epssScore > cond.value) {
            violations.push({
              ruleId: rule.id,
              ruleName: rule.name,
              message: `${vuln.id} has EPSS score ${(vuln.epssScore * 100).toFixed(1)}% (max: ${(cond.value * 100).toFixed(0)}%)`,
              severity: rule.severity,
              dependency: `${result.dependency.name}@${result.dependency.version}`,
              vulnerability: vuln.id,
            });
          }
        }
      }
      break;
    }

    case "no_copyleft": {
      // This requires license data from the report
      if (report.metrics && report.metrics.copyleftCount > 0) {
        violations.push({
          ruleId: rule.id,
          ruleName: rule.name,
          message: `Found ${report.metrics.copyleftCount} copyleft-licensed dependencies`,
          severity: rule.severity,
        });
      }
      break;
    }

    case "no_unknown_license": {
      if (report.metrics && report.metrics.unknownLicenseCount > 0) {
        violations.push({
          ruleId: rule.id,
          ruleName: rule.name,
          message: `Found ${report.metrics.unknownLicenseCount} dependencies with unknown licenses`,
          severity: rule.severity,
        });
      }
      break;
    }

    case "max_vuln_age": {
      const cutoff = Date.now() - cond.days * 24 * 60 * 60 * 1000;
      for (const result of report.results) {
        for (const vuln of result.vulnerabilities) {
          if (vuln.published) {
            const publishDate = new Date(vuln.published).getTime();
            if (publishDate < cutoff && !vuln.fixed_version) {
              const ageDays = Math.floor((Date.now() - publishDate) / (24 * 60 * 60 * 1000));
              violations.push({
                ruleId: rule.id,
                ruleName: rule.name,
                message: `${vuln.id} is ${ageDays} days old with no fix (max: ${cond.days} days)`,
                severity: rule.severity,
                dependency: `${result.dependency.name}@${result.dependency.version}`,
                vulnerability: vuln.id,
              });
            }
          }
        }
      }
      break;
    }
  }

  return violations;
}
