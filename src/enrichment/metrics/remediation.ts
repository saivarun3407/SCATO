// ═══════════════════════════════════════════════════════════════
// High-Impact Remediation Engine
// Cuts through vulnerability noise to give developers a short,
// prioritized action list with the highest ROI for risk reduction.
//
// Priority weighting (informed by OWASP Risk Rating):
//   1. CISA KEV — actively exploited in the wild (highest weight)
//   2. EPSS — probability of exploitation in next 30 days
//   3. CVSS vector — network-accessible RCEs > local exploits
//   4. Severity — CRITICAL > HIGH > MEDIUM > LOW
//   5. Fix availability — fixable vulns get priority over unfixable
//
// ROI = (risk_removed / total_risk) per single library upgrade
// ═══════════════════════════════════════════════════════════════

import type { ScanResult, Vulnerability, Severity } from "../../types.js";

// ─── Output types ───

export interface RemediationAction {
  /** Library to upgrade */
  packageName: string;
  currentVersion: string;
  ecosystem: string;
  /** Recommended version (best fix_version across all vulns) */
  fixVersion: string | null;
  /** Is it a direct dependency? */
  isDirect: boolean;
  /** Parent package (for transitive deps) */
  parent?: string;

  /** Number of vulnerabilities fixed by this upgrade */
  vulnCount: number;
  /** Breakdown by severity */
  severityCounts: Record<string, number>;
  /** Number of KEV (actively exploited) vulns fixed */
  kevCount: number;
  /** Highest EPSS score among the vulns */
  maxEpss: number;
  /** Highest CVSS score among the vulns */
  maxCvss: number;
  /** Whether any vuln is network-accessible RCE */
  hasNetworkRce: boolean;

  /** Composite threat score for this package (0-100) */
  threatScore: number;
  /** Estimated risk reduction as percentage of total project risk */
  riskReductionPct: number;

  /** Individual CVEs fixed */
  cves: RemediationCve[];

  /** Developer-friendly explanation */
  reason: string;
}

export interface RemediationCve {
  id: string;
  severity: Severity;
  score?: number;
  isKev: boolean;
  epss?: number;
  summary: string;
  fixVersion?: string;
}

export interface RemediationReport {
  /** Top N prioritized actions */
  actions: RemediationAction[];
  /** Total project risk score (for ROI calculation) */
  totalProjectRisk: number;
  /** Total vulnerabilities across all results */
  totalVulns: number;
  /** How many vulns the top actions would fix */
  topActionsFixCount: number;
  /** Risk reduction if all top actions are taken */
  topActionsRiskReduction: number;
  /** Summary sentence */
  summary: string;
}

// ─── Scoring constants ───

const WEIGHT_KEV = 40;         // KEV is the highest signal
const WEIGHT_EPSS = 25;        // EPSS probability
const WEIGHT_CVSS_VECTOR = 15; // Attack vector analysis
const WEIGHT_SEVERITY = 15;    // Raw severity
const WEIGHT_FIX_AVAILABLE = 5; // Bonus for fixable vulns

const SEVERITY_SCORES: Record<string, number> = {
  CRITICAL: 1.0,
  HIGH: 0.75,
  MEDIUM: 0.45,
  LOW: 0.2,
  UNKNOWN: 0.1,
};

// ─── Core algorithm ───

/**
 * Analyze scan results and produce a prioritized remediation report.
 * Groups vulnerabilities by library, scores each, and returns top N actions.
 */
export function computeRemediation(
  results: ScanResult[],
  topN: number = 5
): RemediationReport {
  // Step 1: Filter to results that have vulnerabilities
  const vulnResults = results.filter(
    (r) => r.vulnerabilities && r.vulnerabilities.length > 0
  );

  if (vulnResults.length === 0) {
    return {
      actions: [],
      totalProjectRisk: 0,
      totalVulns: 0,
      topActionsFixCount: 0,
      topActionsRiskReduction: 0,
      summary: "No vulnerabilities found — your project is clean.",
    };
  }

  // Step 2: Calculate total project risk (sum of all vuln threat scores)
  let totalProjectRisk = 0;
  const allVulnScores: number[] = [];

  for (const result of vulnResults) {
    for (const vuln of result.vulnerabilities) {
      const score = scoreVulnerability(vuln);
      totalProjectRisk += score;
      allVulnScores.push(score);
    }
  }

  // Step 3: Score each library (package) by aggregating its vuln scores
  const actions: RemediationAction[] = [];

  for (const result of vulnResults) {
    const dep = result.dependency;
    const vulns = result.vulnerabilities;

    // Aggregate metrics
    let packageThreatScore = 0;
    let kevCount = 0;
    let maxEpss = 0;
    let maxCvss = 0;
    let hasNetworkRce = false;
    const sevCounts: Record<string, number> = {};
    const cves: RemediationCve[] = [];
    let bestFixVersion: string | null = null;
    let bestFixSemver = "";

    for (const vuln of vulns) {
      const vulnScore = scoreVulnerability(vuln);
      packageThreatScore += vulnScore;

      // KEV
      if (vuln.isKnownExploited) kevCount++;

      // EPSS
      if (vuln.epssScore && vuln.epssScore > maxEpss) maxEpss = vuln.epssScore;

      // CVSS
      if (vuln.score && vuln.score > maxCvss) maxCvss = vuln.score;

      // Network RCE check
      if (isNetworkRce(vuln)) hasNetworkRce = true;

      // Severity counts
      const sev = (vuln.severity || "UNKNOWN").toUpperCase();
      sevCounts[sev] = (sevCounts[sev] || 0) + 1;

      // Best fix version (highest)
      if (vuln.fixed_version) {
        if (!bestFixVersion || compareVersions(vuln.fixed_version, bestFixSemver) > 0) {
          bestFixVersion = vuln.fixed_version;
          bestFixSemver = vuln.fixed_version;
        }
      }

      cves.push({
        id: vuln.id,
        severity: vuln.severity,
        score: vuln.score,
        isKev: !!vuln.isKnownExploited,
        epss: vuln.epssScore,
        summary: vuln.summary || "",
        fixVersion: vuln.fixed_version,
      });
    }

    // ROI: what percentage of total risk does fixing this library remove?
    const riskReductionPct =
      totalProjectRisk > 0
        ? Math.round((packageThreatScore / totalProjectRisk) * 1000) / 10
        : 0;

    // Normalize threat score to 0-100
    const maxPossibleScore = vulns.length * 100;
    const normalizedThreat = Math.min(
      100,
      Math.round((packageThreatScore / Math.max(maxPossibleScore, 1)) * 100)
    );

    // Generate developer-friendly reason
    const reason = generateReason(
      dep.name,
      dep.version,
      bestFixVersion,
      vulns.length,
      kevCount,
      maxEpss,
      maxCvss,
      hasNetworkRce,
      sevCounts,
      riskReductionPct
    );

    actions.push({
      packageName: dep.name,
      currentVersion: dep.version,
      ecosystem: dep.ecosystem,
      fixVersion: bestFixVersion,
      isDirect: dep.isDirect,
      parent: dep.parent,
      vulnCount: vulns.length,
      severityCounts: sevCounts,
      kevCount,
      maxEpss,
      maxCvss,
      hasNetworkRce,
      threatScore: normalizedThreat,
      riskReductionPct,
      cves,
      reason,
    });
  }

  // Step 4: Sort by threat score descending (highest ROI first)
  actions.sort((a, b) => {
    // KEV-bearing packages always come first
    if (a.kevCount > 0 && b.kevCount === 0) return -1;
    if (b.kevCount > 0 && a.kevCount === 0) return 1;
    // Then by threat score
    if (b.threatScore !== a.threatScore) return b.threatScore - a.threatScore;
    // Tie-break by EPSS
    return b.maxEpss - a.maxEpss;
  });

  // Step 5: Take top N
  const topActions = actions.slice(0, topN);
  const topFixCount = topActions.reduce((sum, a) => sum + a.vulnCount, 0);
  const topRiskReduction = topActions.reduce(
    (sum, a) => sum + a.riskReductionPct,
    0
  );
  const totalVulns = vulnResults.reduce(
    (sum, r) => sum + r.vulnerabilities.length,
    0
  );

  // Generate summary
  const summary = generateSummary(
    topActions,
    topFixCount,
    totalVulns,
    topRiskReduction
  );

  return {
    actions: topActions,
    totalProjectRisk: Math.round(totalProjectRisk),
    totalVulns,
    topActionsFixCount: topFixCount,
    topActionsRiskReduction: Math.round(topRiskReduction * 10) / 10,
    summary,
  };
}

// ─── Vulnerability scoring ───

/** Score a single vulnerability (0-100 scale) */
function scoreVulnerability(vuln: Vulnerability): number {
  let score = 0;

  // 1. KEV: 40 points if actively exploited
  if (vuln.isKnownExploited) {
    score += WEIGHT_KEV;
  }

  // 2. EPSS: up to 25 points based on exploitation probability
  const epss = vuln.epssScore || 0;
  score += epss * WEIGHT_EPSS;

  // 3. CVSS Vector analysis: up to 15 points
  score += analyzeVector(vuln) * WEIGHT_CVSS_VECTOR;

  // 4. Severity: up to 15 points
  const sevKey = (vuln.severity || "UNKNOWN").toUpperCase();
  score += (SEVERITY_SCORES[sevKey] || 0.1) * WEIGHT_SEVERITY;

  // 5. Fix available: 5 bonus points (actionable = higher ROI)
  if (vuln.fixed_version) {
    score += WEIGHT_FIX_AVAILABLE;
  }

  return score;
}

/** Analyze CVSS vector string for attack characteristics (0.0-1.0) */
function analyzeVector(vuln: Vulnerability): number {
  const vector = vuln.cvssVector || "";
  let vectorScore = 0;

  // Attack Vector: Network (1.0) > Adjacent (0.6) > Local (0.3) > Physical (0.1)
  if (vector.includes("AV:N")) vectorScore += 0.4;
  else if (vector.includes("AV:A")) vectorScore += 0.24;
  else if (vector.includes("AV:L")) vectorScore += 0.12;
  else if (vector.includes("AV:P")) vectorScore += 0.04;
  else {
    // No vector info: estimate from CVSS score
    const cvss = vuln.score || 0;
    vectorScore += cvss >= 9.0 ? 0.3 : cvss >= 7.0 ? 0.2 : 0.1;
  }

  // Attack Complexity: Low (0.3) > High (0.1)
  if (vector.includes("AC:L")) vectorScore += 0.3;
  else if (vector.includes("AC:H")) vectorScore += 0.1;
  else vectorScore += 0.15;

  // User Interaction: None (0.2) > Required (0.05)
  if (vector.includes("UI:N")) vectorScore += 0.2;
  else if (vector.includes("UI:R")) vectorScore += 0.05;
  else vectorScore += 0.1;

  // Scope: Changed (0.1) > Unchanged (0)
  if (vector.includes("S:C")) vectorScore += 0.1;

  return Math.min(1.0, vectorScore);
}

/** Check if vulnerability is a network-accessible RCE */
function isNetworkRce(vuln: Vulnerability): boolean {
  const vector = vuln.cvssVector || "";
  const isNetwork = vector.includes("AV:N");
  const isHighImpact =
    vector.includes("C:H") && vector.includes("I:H") && vector.includes("A:H");
  const cwes = vuln.cwes || [];
  const isRceCwe =
    cwes.some(
      (c) =>
        c.includes("CWE-94") ||  // Code Injection
        c.includes("CWE-78") ||  // OS Command Injection
        c.includes("CWE-502") || // Deserialization
        c.includes("CWE-787") || // OOB Write
        c.includes("CWE-119")    // Buffer Overflow
    );

  return isNetwork && (isHighImpact || isRceCwe);
}

/** Simple semver-ish comparison (returns >0 if a > b) */
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

// ─── Developer-friendly output ───

function generateReason(
  name: string,
  currentVersion: string,
  fixVersion: string | null,
  vulnCount: number,
  kevCount: number,
  maxEpss: number,
  maxCvss: number,
  hasNetworkRce: boolean,
  sevCounts: Record<string, number>,
  riskReductionPct: number
): string {
  const parts: string[] = [];

  // Action line
  if (fixVersion) {
    parts.push(`Update ${name} from ${currentVersion} to ${fixVersion}.`);
  } else {
    parts.push(`Review ${name}@${currentVersion} — no fix version available yet.`);
  }

  // What it fixes
  const sevParts: string[] = [];
  if (sevCounts["CRITICAL"]) sevParts.push(`${sevCounts["CRITICAL"]} Critical`);
  if (sevCounts["HIGH"]) sevParts.push(`${sevCounts["HIGH"]} High`);
  if (sevCounts["MEDIUM"]) sevParts.push(`${sevCounts["MEDIUM"]} Medium`);
  if (sevCounts["LOW"]) sevParts.push(`${sevCounts["LOW"]} Low`);

  parts.push(
    `This fixes ${vulnCount} vulnerabilit${vulnCount === 1 ? "y" : "ies"} (${sevParts.join(", ")}).`
  );

  // Why it's urgent
  const urgency: string[] = [];
  if (kevCount > 0) {
    urgency.push(
      `${kevCount} ${kevCount === 1 ? "is" : "are"} actively exploited in the wild (CISA KEV)`
    );
  }
  if (maxEpss >= 0.5) {
    urgency.push(
      `EPSS predicts ${(maxEpss * 100).toFixed(0)}% chance of exploitation in 30 days`
    );
  }
  if (hasNetworkRce) {
    urgency.push("includes a network-accessible Remote Code Execution");
  }
  if (urgency.length > 0) {
    parts.push("Why: " + urgency.join("; ") + ".");
  }

  // ROI
  if (riskReductionPct >= 1) {
    parts.push(
      `This single update reduces your project risk by ${riskReductionPct}%.`
    );
  }

  return parts.join(" ");
}

function generateSummary(
  topActions: RemediationAction[],
  topFixCount: number,
  totalVulns: number,
  topRiskReduction: number
): string {
  if (topActions.length === 0) {
    return "No actionable remediations found.";
  }

  const kevActions = topActions.filter((a) => a.kevCount > 0);
  const fixableActions = topActions.filter((a) => a.fixVersion);

  let summary = `Top ${topActions.length} fixes address ${topFixCount} of ${totalVulns} vulnerabilities`;
  summary += ` (${Math.round(topRiskReduction)}% risk reduction).`;

  if (kevActions.length > 0) {
    const totalKev = kevActions.reduce((s, a) => s + a.kevCount, 0);
    summary += ` ${totalKev} actively exploited (KEV) vulnerabilit${totalKev === 1 ? "y" : "ies"} included.`;
  }

  if (fixableActions.length > 0) {
    summary += ` ${fixableActions.length} of ${topActions.length} have fix versions available.`;
  }

  return summary;
}
