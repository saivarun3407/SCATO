// ─── Metrics Calculator ───
// Computes risk scores and analytics from scan results

import type {
  ScanReport,
  ScanResult,
  ScanMetrics,
  Severity,
  Vulnerability,
} from "../../types.js";
import { detectLicense } from "../license/detector.js";

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  CRITICAL: 10,
  HIGH: 5,
  MEDIUM: 2,
  LOW: 0.5,
  UNKNOWN: 0.25,
};

export function calculateMetrics(report: ScanReport): ScanMetrics {
  const allVulns: Vulnerability[] = report.results.flatMap((r) => r.vulnerabilities);

  // Risk score calculation (0-100)
  const riskScore = calculateRiskScore(report.results, allVulns);
  const riskLevel = riskScoreToLevel(riskScore);

  // Fix availability
  const criticalWithFix = allVulns.filter(
    (v) => v.severity === "CRITICAL" && v.fixed_version
  ).length;
  const highWithFix = allVulns.filter(
    (v) => v.severity === "HIGH" && v.fixed_version
  ).length;

  // Vulnerability age
  const ages = allVulns
    .filter((v) => v.published)
    .map((v) => {
      const pubDate = new Date(v.published).getTime();
      return Math.max(0, Math.floor((Date.now() - pubDate) / (24 * 60 * 60 * 1000)));
    })
    .sort((a, b) => a - b);

  const medianVulnAge = ages.length > 0 ? ages[Math.floor(ages.length / 2)] : 0;

  // Oldest unfixed
  let oldestUnfixedVuln: ScanMetrics["oldestUnfixedVuln"] = undefined;
  const unfixed = allVulns
    .filter((v) => !v.fixed_version && v.published)
    .map((v) => ({
      id: v.id,
      severity: v.severity,
      age: Math.floor((Date.now() - new Date(v.published).getTime()) / (24 * 60 * 60 * 1000)),
    }))
    .sort((a, b) => b.age - a.age);

  if (unfixed.length > 0) {
    oldestUnfixedVuln = unfixed[0];
  }

  // KEV metrics
  const kevVulns = allVulns.filter((v) => v.isKnownExploited);
  const kevCount = kevVulns.length;
  const kevWithFix = kevVulns.filter((v) => v.fixed_version).length;

  // EPSS metrics
  const epssScores = allVulns
    .filter((v) => v.epssScore !== undefined)
    .map((v) => v.epssScore!);

  const avgEpssScore =
    epssScores.length > 0
      ? epssScores.reduce((sum, s) => sum + s, 0) / epssScores.length
      : 0;
  const maxEpssScore = epssScores.length > 0 ? Math.max(...epssScores) : 0;
  const highEpssCount = epssScores.filter((s) => s > 0.5).length;

  // License metrics
  let copyleftCount = 0;
  let unknownLicenseCount = 0;
  const uniqueLicenseSet = new Set<string>();

  for (const result of report.results) {
    const dep = result.dependency;
    if (dep.license) {
      uniqueLicenseSet.add(dep.license);
      const info = detectLicense(dep.license);
      if (info?.isCopyleft) copyleftCount++;
    } else {
      unknownLicenseCount++;
    }
  }

  // Dependency metrics
  const directDeps = report.results.filter((r) => r.dependency.isDirect).length;
  const transitiveDeps = report.results.filter((r) => !r.dependency.isDirect).length;
  const maxDepth = report.dependencyTrees
    ? Math.max(0, ...report.dependencyTrees.map((t) => t.maxDepth))
    : 0;

  return {
    riskScore,
    riskLevel,
    criticalWithFix,
    highWithFix,
    medianVulnAge,
    oldestUnfixedVuln,
    kevCount,
    kevWithFix,
    avgEpssScore,
    maxEpssScore,
    highEpssCount,
    copyleftCount,
    unknownLicenseCount,
    uniqueLicenses: uniqueLicenseSet.size,
    directDependencies: directDeps,
    transitiveDependencies: transitiveDeps,
    maxDepth,
    outdatedCount: 0, // requires version comparison — future enhancement
  };
}

function calculateRiskScore(
  results: ScanResult[],
  allVulns: Vulnerability[]
): number {
  if (allVulns.length === 0) return 0;

  let rawScore = 0;

  for (const vuln of allVulns) {
    let weight = SEVERITY_WEIGHTS[vuln.severity];

    // KEV multiplier — actively exploited vulns are highest priority
    if (vuln.isKnownExploited) weight *= 3;

    // EPSS multiplier — high exploitation probability
    if (vuln.epssScore && vuln.epssScore > 0.5) weight *= 1.5;

    // Direct dependency multiplier
    const result = results.find((r) =>
      r.vulnerabilities.some((v) => v.id === vuln.id)
    );
    if (result?.dependency.isDirect) weight *= 1.25;

    // Reduce weight if fix is available (still bad, but remediable)
    if (vuln.fixed_version) weight *= 0.8;

    rawScore += weight;
  }

  // Normalize to 0-100 using logarithmic scaling
  // Score of 1 vuln at CRITICAL = ~25, 5 CRITICAL = ~60, etc.
  const normalized = Math.min(100, Math.round(20 * Math.log2(rawScore + 1)));

  return normalized;
}

function riskScoreToLevel(score: number): ScanMetrics["riskLevel"] {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  if (score > 0) return "low";
  return "none";
}
