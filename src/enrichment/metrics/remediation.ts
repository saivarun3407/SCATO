// ═══════════════════════════════════════════════════════════════
// Prioritized Remediation Engine
// Produces a quantified, ranked remediation plan by scoring every
// vulnerability across five weighted dimensions and aggregating
// per-package risk.  Addresses "sum of lows" fallacy and aligns
// ROI % with ranking (KEV multiplier).  See docs/REMEDIATION_SCORING.md.
//
// Per-CVE weights (sum = 100): KEV 30, EPSS 20, Vector 15, Severity 30, Fix 5.
// Severity is exponential: CRITICAL=30, HIGH=15, MED=4.5, LOW=0.9, UNK=0.3.
//
// Aggregation: Package base risk = max(CVE score) + sum(rest) × DAMPENER (0.1).
// Adjusted risk = base × (KEV_MULTIPLIER if any KEV else 1). ROI uses adjusted.
// ═══════════════════════════════════════════════════════════════

import type { ScanResult, Vulnerability, Severity } from "../../types.js";

// ─── Output types ───

export interface ScoreBreakdown {
  kev: number;
  epss: number;
  vector: number;
  severity: number;
  fix: number;
}

export interface RemediationCve {
  id: string;
  severity: Severity;
  cvss: number;
  epss: number;
  isKev: boolean;
  score: number;
  breakdown: ScoreBreakdown;
  attackVector: string;
  fixVersion: string | null;
  summary: string;
}

export interface RemediationAction {
  packageName: string;
  currentVersion: string;
  ecosystem: string;
  fixVersion: string | null;
  /** Latest version available on the registry (populated async) */
  latestVersion?: string;
  isDirect: boolean;
  parent?: string;

  vulnCount: number;
  fixCoverage: number;           // how many CVEs have a fix
  severityCounts: Record<string, number>;
  kevCount: number;
  maxEpss: number;
  maxCvss: number;
  hasNetworkRce: boolean;
  attackVectors: string[];

  /** Adjusted risk score (base risk × KEV multiplier if applicable); used for ROI and ranking */
  riskScore: number;
  /** Base risk before KEV multiplier (max + dampened sum of remaining CVE scores) */
  baseRiskScore: number;
  /** Percentage of total project risk this package represents (based on adjusted risk) */
  riskReductionPct: number;
  /** Score breakdown aggregated across all CVEs */
  breakdown: ScoreBreakdown;
  /** One-line "why this ranks here" from top CVE, e.g. "1 Critical RCE (AV:N)" */
  riskDominator: string;

  cves: RemediationCve[];
}

export interface RemediationReport {
  actions: RemediationAction[];
  totalRiskScore: number;
  totalVulnCount: number;
  totalKevCount: number;
  totalCriticalCount: number;
  totalHighCount: number;
  totalPackages: number;
  maxScorePerCve: number;
  summary: string;
}

// ─── Scoring constants ───

const WEIGHT_KEV = 30;
const WEIGHT_EPSS = 20;
const WEIGHT_CVSS_VECTOR = 15;
const WEIGHT_SEVERITY = 30;
const WEIGHT_FIX_AVAILABLE = 5;
const MAX_SCORE_PER_CVE = WEIGHT_KEV + WEIGHT_EPSS + WEIGHT_CVSS_VECTOR + WEIGHT_SEVERITY + WEIGHT_FIX_AVAILABLE;

/** Dampener for aggregation: prevents "sum of lows" from eclipsing a single Critical. Configurable 0.05–0.2. */
const DAMPENER = 0.1;

/** KEV multiplier for ROI alignment: packages with KEV show higher risk reduction % so ranking matches impact. Capped 2–3×. */
const KEV_MULTIPLIER = 2.5;

/** Exponential severity: Critical ~33× Low to reflect cascade risk (FAIR-style). */
const SEVERITY_SCORES: Record<string, number> = {
  CRITICAL: 1.0,
  HIGH: 0.5,
  MEDIUM: 0.15,
  LOW: 0.03,
  UNKNOWN: 0.01,
};

// ─── Core algorithm ───

export function computeRemediation(
  results: ScanResult[],
  topN: number = 5
): RemediationReport {
  const vulnResults = results.filter(
    (r) => r.vulnerabilities && r.vulnerabilities.length > 0
  );

  if (vulnResults.length === 0) {
    return {
      actions: [],
      totalRiskScore: 0,
      totalVulnCount: 0,
      totalKevCount: 0,
      totalCriticalCount: 0,
      totalHighCount: 0,
      totalPackages: results.length,
      maxScorePerCve: MAX_SCORE_PER_CVE,
      summary: "No vulnerabilities detected. Project is clean.",
    };
  }

  let totalRiskScore = 0;
  let totalVulnCount = 0;
  let totalKevCount = 0;
  let totalCriticalCount = 0;
  let totalHighCount = 0;

  const actions: RemediationAction[] = [];

  for (const result of vulnResults) {
    const dep = result.dependency;
    const vulns = result.vulnerabilities;

    let kevCount = 0;
    let maxEpss = 0;
    let maxCvss = 0;
    let hasNetworkRce = false;
    let fixCoverage = 0;
    const sevCounts: Record<string, number> = {};
    const cves: RemediationCve[] = [];
    const pkgBreakdown: ScoreBreakdown = { kev: 0, epss: 0, vector: 0, severity: 0, fix: 0 };
    const avSet = new Set<string>();
    let bestFixVersion: string | null = null;
    const cveScores: number[] = [];

    for (const vuln of vulns) {
      const scored = scoreVulnerability(vuln);
      cveScores.push(scored.score);

      pkgBreakdown.kev += scored.breakdown.kev;
      pkgBreakdown.epss += scored.breakdown.epss;
      pkgBreakdown.vector += scored.breakdown.vector;
      pkgBreakdown.severity += scored.breakdown.severity;
      pkgBreakdown.fix += scored.breakdown.fix;

      if (vuln.isKnownExploited) { kevCount++; totalKevCount++; }
      if ((vuln.epssScore || 0) > maxEpss) maxEpss = vuln.epssScore || 0;
      if ((vuln.score || 0) > maxCvss) maxCvss = vuln.score || 0;
      if (isNetworkRce(vuln)) hasNetworkRce = true;

      const sev = (vuln.severity || "UNKNOWN").toUpperCase();
      sevCounts[sev] = (sevCounts[sev] || 0) + 1;
      if (sev === "CRITICAL") totalCriticalCount++;
      if (sev === "HIGH") totalHighCount++;

      if (vuln.fixed_version) {
        fixCoverage++;
        if (!bestFixVersion || compareVersions(vuln.fixed_version, bestFixVersion) > 0) {
          bestFixVersion = vuln.fixed_version;
        }
      }

      const av = getAttackVector(vuln);
      avSet.add(av);

      cves.push({
        id: vuln.id,
        severity: vuln.severity,
        cvss: vuln.score || 0,
        epss: vuln.epssScore || 0,
        isKev: !!vuln.isKnownExploited,
        score: scored.score,
        breakdown: scored.breakdown,
        attackVector: av,
        fixVersion: vuln.fixed_version || null,
        summary: vuln.summary || "",
      });

      totalVulnCount++;
    }

    // Aggregation: max + dampened sum (prevents "sum of lows" eclipsing single Critical)
    cveScores.sort((a, b) => b - a);
    const maxScore = cveScores[0] ?? 0;
    const restSum = cveScores.slice(1).reduce((acc, val) => acc + val, 0);
    const baseRiskScore = round(maxScore + restSum * DAMPENER);
    const hasKEV = kevCount > 0;
    const adjustedRiskScore = round(hasKEV ? baseRiskScore * KEV_MULTIPLIER : baseRiskScore);
    totalRiskScore += adjustedRiskScore;

    // Sort CVEs by score descending (top CVE first for riskDominator)
    cves.sort((a, b) => b.score - a.score);

    // Round for clean output
    pkgBreakdown.kev = round(pkgBreakdown.kev);
    pkgBreakdown.epss = round(pkgBreakdown.epss);
    pkgBreakdown.vector = round(pkgBreakdown.vector);
    pkgBreakdown.severity = round(pkgBreakdown.severity);
    pkgBreakdown.fix = round(pkgBreakdown.fix);

    // One-line "why this ranks here" from top CVE
    const topCve = cves[0];
    const riskDominator = topCve
      ? formatRiskDominator(topCve, sevCounts)
      : "No CVEs";

    actions.push({
      packageName: dep.name,
      currentVersion: dep.version,
      ecosystem: dep.ecosystem,
      fixVersion: bestFixVersion,
      isDirect: dep.isDirect,
      parent: dep.parent,
      vulnCount: vulns.length,
      fixCoverage,
      severityCounts: sevCounts,
      kevCount,
      maxEpss,
      maxCvss,
      hasNetworkRce,
      attackVectors: Array.from(avSet),
      riskScore: adjustedRiskScore,
      baseRiskScore,
      riskReductionPct: 0, // calculated after totalRiskScore known
      breakdown: pkgBreakdown,
      riskDominator,
      cves,
    });
  }

  totalRiskScore = round(totalRiskScore);

  // Calculate ROI for each action (using adjusted risk so ROI aligns with ranking)
  for (const action of actions) {
    action.riskReductionPct =
      totalRiskScore > 0
        ? round((action.riskScore / totalRiskScore) * 100, 1)
        : 0;
  }

  // Sort: KEV first, then adjusted risk score, then EPSS, then fewer CVEs = better
  actions.sort((a, b) => {
    if (a.kevCount > 0 && b.kevCount === 0) return -1;
    if (b.kevCount > 0 && a.kevCount === 0) return 1;
    if (b.riskScore !== a.riskScore) return b.riskScore - a.riskScore;
    if (b.maxEpss !== a.maxEpss) return b.maxEpss - a.maxEpss;
    return a.vulnCount - b.vulnCount; // fewer CVEs = higher priority (simpler fix)
  });

  const topActions = actions.slice(0, topN);
  const topFixCount = topActions.reduce((s, a) => s + a.vulnCount, 0);
  const topRiskReduction = topActions.reduce((s, a) => s + a.riskReductionPct, 0);

  const summary = generateSummary(topActions, topFixCount, totalVulnCount, topRiskReduction, totalRiskScore, totalKevCount);

  return {
    actions: topActions,
    totalRiskScore,
    totalVulnCount,
    totalKevCount,
    totalCriticalCount,
    totalHighCount,
    totalPackages: results.length,
    maxScorePerCve: MAX_SCORE_PER_CVE,
    summary,
  };
}

// ─── Vulnerability scoring ───

function scoreVulnerability(vuln: Vulnerability): { score: number; breakdown: ScoreBreakdown } {
  const breakdown: ScoreBreakdown = { kev: 0, epss: 0, vector: 0, severity: 0, fix: 0 };

  if (vuln.isKnownExploited) breakdown.kev = WEIGHT_KEV;
  breakdown.epss = round((vuln.epssScore || 0) * WEIGHT_EPSS);

  const vectorResult = analyzeVector(vuln);
  breakdown.vector = round(vectorResult * WEIGHT_CVSS_VECTOR);

  const sevKey = (vuln.severity || "UNKNOWN").toUpperCase();
  breakdown.severity = round((SEVERITY_SCORES[sevKey] || 0.1) * WEIGHT_SEVERITY);

  if (vuln.fixed_version) breakdown.fix = WEIGHT_FIX_AVAILABLE;

  const score = round(breakdown.kev + breakdown.epss + breakdown.vector + breakdown.severity + breakdown.fix);
  return { score, breakdown };
}

function analyzeVector(vuln: Vulnerability): number {
  const vector = vuln.cvssVector || "";
  let s = 0;

  if (vector.includes("AV:N")) s += 0.4;
  else if (vector.includes("AV:A")) s += 0.24;
  else if (vector.includes("AV:L")) s += 0.12;
  else if (vector.includes("AV:P")) s += 0.04;
  else {
    const cvss = vuln.score || 0;
    s += cvss >= 9.0 ? 0.3 : cvss >= 7.0 ? 0.2 : 0.1;
  }

  if (vector.includes("AC:L")) s += 0.3;
  else if (vector.includes("AC:H")) s += 0.1;
  else s += 0.15;

  if (vector.includes("UI:N")) s += 0.2;
  else if (vector.includes("UI:R")) s += 0.05;
  else s += 0.1;

  if (vector.includes("S:C")) s += 0.1;

  return Math.min(1.0, s);
}

function getAttackVector(vuln: Vulnerability): string {
  const vec = vuln.cvssVector || "";
  if (vec.includes("AV:N")) return "Network";
  if (vec.includes("AV:A")) return "Adjacent";
  if (vec.includes("AV:L")) return "Local";
  if (vec.includes("AV:P")) return "Physical";
  return "Unknown";
}

function isNetworkRce(vuln: Vulnerability): boolean {
  const vector = vuln.cvssVector || "";
  if (!vector.includes("AV:N")) return false;
  const highImpact = vector.includes("C:H") && vector.includes("I:H");
  const cwes = vuln.cwes || [];
  const isRceCwe = cwes.some(
    (c) =>
      c.includes("CWE-94") ||
      c.includes("CWE-78") ||
      c.includes("CWE-502") ||
      c.includes("CWE-787") ||
      c.includes("CWE-119")
  );
  return highImpact || isRceCwe;
}

function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na !== nb) return na - nb;
  }
  return 0;
}

function round(n: number, decimals = 2): number {
  const f = Math.pow(10, decimals);
  return Math.round(n * f) / f;
}

/** One-line "why this ranks here" from top CVE, e.g. "1 Critical RCE (AV:N)" */
function formatRiskDominator(topCve: RemediationCve, _sevCounts: Record<string, number>): string {
  const sev = (topCve.severity || "UNKNOWN").toString().toUpperCase();
  const av = topCve.attackVector || "Unknown";
  const rce = topCve.attackVector === "Network" && (topCve.cvss >= 9 || sev === "CRITICAL" || sev === "HIGH") ? " RCE" : "";
  return `1 ${sev}${rce} (${av})`;
}

// ─── Summary generation ───

function generateSummary(
  topActions: RemediationAction[],
  topFixCount: number,
  totalVulns: number,
  topRiskReduction: number,
  totalRiskScore: number,
  totalKevCount: number
): string {
  if (topActions.length === 0) return "No actionable remediations identified.";

  let summary = `Fixing ${topActions.length} packages resolves ${topFixCount} of ${totalVulns} vulnerabilities`;
  summary += ` (${Math.round(topRiskReduction)}% of ${totalRiskScore} total risk points).`;

  if (totalKevCount > 0) {
    summary += ` ${totalKevCount} CVE${totalKevCount > 1 ? "s" : ""} confirmed actively exploited (CISA KEV).`;
  }

  const fixable = topActions.filter((a) => a.fixVersion).length;
  if (fixable > 0) {
    summary += ` ${fixable}/${topActions.length} have fix versions available.`;
  }

  return summary;
}
