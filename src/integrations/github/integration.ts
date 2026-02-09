// ─── GitHub Integration ───
// PR comments, check runs, and issue creation for vulnerability findings

import type {
  ScanReport,
  GitHubContext,
  CheckRunResult,
  Severity,
} from "../../types.js";

export function detectGitHubContext(): GitHubContext | null {
  const token = process.env.GITHUB_TOKEN;
  const repository = process.env.GITHUB_REPOSITORY;
  const sha = process.env.GITHUB_SHA;

  if (!token || !repository || !sha) return null;

  const [owner, repo] = repository.split("/");
  if (!owner || !repo) return null;

  let prNumber: number | undefined;
  const eventName = process.env.GITHUB_EVENT_NAME;
  if (eventName === "pull_request") {
    const ref = process.env.GITHUB_REF || "";
    const match = ref.match(/refs\/pull\/(\d+)/);
    if (match) prNumber = parseInt(match[1], 10);
  }

  return {
    owner,
    repo,
    sha,
    prNumber,
    token,
    apiUrl: process.env.GITHUB_API_URL || "https://api.github.com",
  };
}

// ─── PR Comment ───

export async function postPRComment(
  ctx: GitHubContext,
  report: ScanReport
): Promise<boolean> {
  if (!ctx.prNumber) return false;

  const body = formatPRComment(report);
  const url = `${ctx.apiUrl}/repos/${ctx.owner}/${ctx.repo}/issues/${ctx.prNumber}/comments`;

  try {
    // First, check for existing SCATO comment and update it
    const existingId = await findExistingComment(ctx);

    if (existingId) {
      const updateUrl = `${ctx.apiUrl}/repos/${ctx.owner}/${ctx.repo}/issues/comments/${existingId}`;
      const res = await fetch(updateUrl, {
        method: "PATCH",
        headers: {
          "Authorization": `Bearer ${ctx.token}`,
          "Accept": "application/vnd.github+json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ body }),
      });
      return res.ok;
    }

    // Create new comment
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${ctx.token}`,
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body }),
    });

    return res.ok;
  } catch {
    return false;
  }
}

async function findExistingComment(ctx: GitHubContext): Promise<number | null> {
  if (!ctx.prNumber) return null;

  const url = `${ctx.apiUrl}/repos/${ctx.owner}/${ctx.repo}/issues/${ctx.prNumber}/comments?per_page=100`;

  try {
    const res = await fetch(url, {
      headers: {
        "Authorization": `Bearer ${ctx.token}`,
        "Accept": "application/vnd.github+json",
      },
    });

    if (!res.ok) return null;

    const comments = (await res.json()) as Array<{ id: number; body: string }>;
    const scatoComment = comments.find((c) =>
      c.body.includes("<!-- scato-scan-report -->")
    );

    return scatoComment?.id || null;
  } catch {
    return null;
  }
}

function formatPRComment(report: ScanReport): string {
  const { severityCounts, totalVulnerabilities, totalDependencies, metrics } = report;
  const passed = totalVulnerabilities === 0;

  let body = `<!-- scato-scan-report -->\n`;
  body += `## ${passed ? "✅" : "🛡️"} SCATO Security Scan\n\n`;

  // Summary table
  body += `| Metric | Value |\n|--------|-------|\n`;
  body += `| Dependencies | ${totalDependencies} |\n`;
  body += `| Vulnerabilities | ${totalVulnerabilities} |\n`;

  if (severityCounts.CRITICAL > 0)
    body += `| 🔴 Critical | ${severityCounts.CRITICAL} |\n`;
  if (severityCounts.HIGH > 0)
    body += `| 🟠 High | ${severityCounts.HIGH} |\n`;
  if (severityCounts.MEDIUM > 0)
    body += `| 🟡 Medium | ${severityCounts.MEDIUM} |\n`;
  if (severityCounts.LOW > 0)
    body += `| 🔵 Low | ${severityCounts.LOW} |\n`;

  if (metrics) {
    body += `| Risk Score | ${metrics.riskScore}/100 |\n`;
    if (metrics.kevCount > 0)
      body += `| ⚠️ Known Exploited (KEV) | ${metrics.kevCount} |\n`;
    if (metrics.highEpssCount > 0)
      body += `| 📈 High EPSS (>50%) | ${metrics.highEpssCount} |\n`;
  }

  body += `\n`;

  // Top vulnerabilities (limit to 10)
  const criticalVulns = report.results
    .flatMap((r) =>
      r.vulnerabilities
        .filter((v) => v.severity === "CRITICAL" || v.severity === "HIGH" || v.isKnownExploited)
        .map((v) => ({
          ...v,
          pkg: `${r.dependency.name}@${r.dependency.version}`,
        }))
    )
    .slice(0, 10);

  if (criticalVulns.length > 0) {
    body += `### Top Findings\n\n`;
    body += `| Vulnerability | Package | Severity | Fix |\n|--------------|---------|----------|-----|\n`;

    for (const v of criticalVulns) {
      const kevBadge = v.isKnownExploited ? " 🔥KEV" : "";
      const fix = v.fixed_version ? `\`${v.fixed_version}\`` : "No fix";
      const epss = v.epssScore ? ` (EPSS: ${(v.epssScore * 100).toFixed(1)}%)` : "";
      body += `| ${v.id}${kevBadge} | \`${v.pkg}\` | ${v.severity}${epss} | ${fix} |\n`;
    }
    body += `\n`;
  }

  // License warnings
  if (metrics && metrics.copyleftCount > 0) {
    body += `### ⚖️ License Warnings\n`;
    body += `Found ${metrics.copyleftCount} copyleft-licensed dependencies and ${metrics.unknownLicenseCount} with unknown licenses.\n\n`;
  }

  body += `---\n`;
  body += `*Scanned at ${report.timestamp} | SCATO v${report.version}*\n`;

  return body;
}

// ─── Check Run ───

export async function createCheckRun(
  ctx: GitHubContext,
  report: ScanReport
): Promise<boolean> {
  const check = buildCheckRun(report);
  const url = `${ctx.apiUrl}/repos/${ctx.owner}/${ctx.repo}/check-runs`;

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${ctx.token}`,
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        name: "SCATO Security Scan",
        head_sha: ctx.sha,
        status: "completed",
        conclusion: check.conclusion,
        output: {
          title: check.title,
          summary: check.summary,
          annotations: check.annotations.slice(0, 50), // GitHub limit
        },
      }),
    });

    return res.ok;
  } catch {
    return false;
  }
}

function buildCheckRun(report: ScanReport): CheckRunResult {
  const { totalVulnerabilities, severityCounts, metrics } = report;

  let conclusion: "success" | "failure" | "neutral" = "success";
  if (severityCounts.CRITICAL > 0 || severityCounts.HIGH > 0) {
    conclusion = "failure";
  } else if (severityCounts.MEDIUM > 0) {
    conclusion = "neutral";
  }

  const title = totalVulnerabilities === 0
    ? "No vulnerabilities found"
    : `Found ${totalVulnerabilities} vulnerabilities`;

  let summary = `Scanned ${report.totalDependencies} dependencies across ${report.ecosystems.join(", ")}.\n\n`;
  summary += `| Severity | Count |\n|----------|-------|\n`;
  summary += `| Critical | ${severityCounts.CRITICAL} |\n`;
  summary += `| High | ${severityCounts.HIGH} |\n`;
  summary += `| Medium | ${severityCounts.MEDIUM} |\n`;
  summary += `| Low | ${severityCounts.LOW} |\n`;

  if (metrics) {
    summary += `\nRisk Score: ${metrics.riskScore}/100 (${metrics.riskLevel})\n`;
  }

  // Build annotations from vulnerabilities
  const annotations: CheckRunResult["annotations"] = [];
  for (const result of report.results) {
    for (const vuln of result.vulnerabilities) {
      if (vuln.severity === "CRITICAL" || vuln.severity === "HIGH") {
        annotations.push({
          path: findManifestFile(result.dependency.ecosystem),
          start_line: 1,
          end_line: 1,
          annotation_level: vuln.severity === "CRITICAL" ? "failure" : "warning",
          message: `${vuln.id}: ${vuln.summary}${vuln.fixed_version ? ` (fix: ${vuln.fixed_version})` : ""}`,
          title: `${result.dependency.name}@${result.dependency.version}`,
        });
      }
    }
  }

  return { conclusion, title, summary, annotations };
}

function findManifestFile(ecosystem: string): string {
  const manifestMap: Record<string, string> = {
    npm: "package.json",
    pip: "requirements.txt",
    go: "go.mod",
    maven: "pom.xml",
    cargo: "Cargo.toml",
    nuget: "packages.config",
    gem: "Gemfile",
    composer: "composer.json",
  };
  return manifestMap[ecosystem] || "package.json";
}
