// ─── Core Scanner Orchestrator (v3) ───
// 5-Phase Pipeline: DISCOVER → QUERY → ANALYZE → OUTPUT → PERSIST
// Core imports only — all optional modules loaded via dynamic import()

import { discoverDependencies } from "./core/parsers/index.js";
import { queryAllSources } from "./core/advisories/aggregator.js";
import { randomUUID } from "crypto";
import type {
  Dependency,
  ScanResult,
  ScanReport,
  Severity,
  Ecosystem,
  VulnerabilitySource,
} from "./types.js";

export interface ScanOptions {
  target: string;
  outputJson?: boolean;
  sbomOutput?: string;
  sbomFormat?: "cyclonedx" | "spdx";
  sarifOutput?: string;
  skipLicenses?: boolean;
  skipDev?: boolean;
  ecosystems?: Ecosystem[];
  sources?: VulnerabilitySource[];
  nvdApiKey?: string;
  githubToken?: string;
  policyFile?: string;
  failOn?: Severity;
  ciMode?: boolean;
  prComment?: boolean;
  checkRun?: boolean;
  cacheDir?: string;
  offlineMode?: boolean;
}

export async function scan(options: ScanOptions): Promise<ScanReport> {
  const { target } = options;
  const startTime = Date.now();
  const scanId = randomUUID();

  // ── Phase 1: DISCOVER ──
  const deps = await discoverDependencies(target, {
    ecosystems: options.ecosystems,
    skipDev: options.skipDev,
  });

  if (deps.length === 0) {
    return emptyReport(target, scanId, Date.now() - startTime);
  }

  const ecosystems = [...new Set(deps.map((d) => d.ecosystem))];

  // Enrich with license info (optional)
  if (!options.skipLicenses) {
    try {
      const { enrichLicenses } = await import("./enrichment/license/detector.js");
      await enrichLicenses(deps);
    } catch { /* license enrichment is optional */ }
  }

  // ── Phase 2: QUERY ──
  const { vulnMap, sourceTimestamps } = await queryAllSources(deps, {
    sources: options.sources,
    nvdApiKey: options.nvdApiKey || process.env.NVD_API_KEY,
    githubToken: options.githubToken || process.env.GITHUB_TOKEN,
  });

  // ── Phase 3: ANALYZE ──
  const results: ScanResult[] = deps.map((dep) => {
    const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    return {
      dependency: dep,
      vulnerabilities: vulnMap.get(key) || [],
    };
  });

  const severityCounts: Record<Severity, number> = {
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0,
  };
  let totalVulnerabilities = 0;
  for (const result of results) {
    for (const vuln of result.vulnerabilities) {
      severityCounts[vuln.severity]++;
      totalVulnerabilities++;
    }
  }

  const report: ScanReport = {
    tool: "scato",
    version: "3.0.0",
    timestamp: new Date().toISOString(),
    target,
    ecosystems,
    totalDependencies: deps.length,
    totalVulnerabilities,
    severityCounts,
    results,
    scanDurationMs: Date.now() - startTime,
    scanId,
    dataSourceTimestamps: sourceTimestamps as any,
  };

  // Build dependency trees (per-ecosystem hierarchy)
  try {
    const { buildDependencyTrees } = await import("./core/tree/builder.js");
    report.dependencyTrees = buildDependencyTrees(results);
  } catch { /* tree build is optional */ }

  // Calculate metrics (optional enrichment)
  try {
    const { calculateMetrics } = await import("./enrichment/metrics/calculator.js");
    report.metrics = calculateMetrics(report);
  } catch { /* metrics are optional */ }

  // Evaluate policy (optional integration)
  try {
    const { loadPolicy, evaluatePolicy } = await import("./integrations/policy/engine.js");
    const policy = await loadPolicy(options.policyFile);
    report.policyResult = evaluatePolicy(report, policy);
  } catch { /* policy is optional */ }

  // ── Phase 4: OUTPUT ──
  if (options.sbomOutput) {
    try {
      const projectName = target.split("/").pop() || "unknown";
      if (options.sbomFormat === "spdx") {
        const { generateSPDX, writeSPDX } = await import("./sbom/spdx.js");
        const doc = generateSPDX(projectName, results);
        await writeSPDX(doc, options.sbomOutput);
      } else {
        const { generateSBOM, writeSBOM } = await import("./sbom/cyclonedx.js");
        const bom = generateSBOM(projectName, results);
        await writeSBOM(bom, options.sbomOutput);
      }
      report.sbomPath = options.sbomOutput;
    } catch { /* SBOM generation is optional */ }
  }

  if (options.sarifOutput) {
    try {
      const { writeSarif } = await import("./integrations/ci/sarif.js");
      await writeSarif(report, options.sarifOutput);
    } catch { /* SARIF is optional */ }
  }

  // ── Phase 5: PERSIST ──
  try {
    const { getDatabase } = await import("./storage/database.js");
    const db = getDatabase(options.cacheDir);
    db.saveScan(report);
  } catch { /* database is optional */ }

  if (options.ciMode) {
    try {
      await handleCIIntegration(report, options);
    } catch { /* CI integration is optional */ }
  }

  report.scanDurationMs = Date.now() - startTime;
  return report;
}

async function handleCIIntegration(
  report: ScanReport,
  options: ScanOptions
): Promise<void> {
  const { detectCI, emitCIAnnotation, setCIOutput } = await import("./integrations/ci/detect.js");
  const ci = detectCI();

  for (const result of report.results) {
    for (const vuln of result.vulnerabilities) {
      if (vuln.severity === "CRITICAL" || vuln.severity === "HIGH") {
        emitCIAnnotation(
          ci.platform,
          vuln.severity === "CRITICAL" ? "error" : "warning",
          `${vuln.id}: ${result.dependency.name}@${result.dependency.version} — ${vuln.summary}`
        );
      }
    }
  }

  setCIOutput(ci.platform, "total_vulnerabilities", String(report.totalVulnerabilities));
  setCIOutput(ci.platform, "risk_score", String(report.metrics?.riskScore || 0));
  setCIOutput(ci.platform, "policy_passed", String(report.policyResult?.passed || false));

  if (ci.platform === "github-actions") {
    const { detectGitHubContext, postPRComment, createCheckRun } = await import("./integrations/github/integration.js");
    const ghCtx = detectGitHubContext();
    if (ghCtx) {
      if (options.prComment !== false && ghCtx.prNumber) {
        await postPRComment(ghCtx, report);
      }
      if (options.checkRun !== false) {
        await createCheckRun(ghCtx, report);
      }
    }
  }
}

function emptyReport(target: string, scanId: string, durationMs: number): ScanReport {
  return {
    tool: "scato",
    version: "3.0.0",
    timestamp: new Date().toISOString(),
    target,
    ecosystems: [],
    totalDependencies: 0,
    totalVulnerabilities: 0,
    severityCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
    results: [],
    scanDurationMs: durationMs,
    scanId,
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
      uniqueLicenses: 0,
      directDependencies: 0,
      transitiveDependencies: 0,
      maxDepth: 0,
      outdatedCount: 0,
    },
    policyResult: { passed: true, violations: [], warnings: [] },
  };
}
