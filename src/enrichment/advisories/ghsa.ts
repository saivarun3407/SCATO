// ─── GitHub Security Advisories (GHSA) Adapter ───
// Uses GitHub GraphQL API for security advisories

import type { Vulnerability, Severity, Ecosystem } from "../../types.js";

const GITHUB_API = "https://api.github.com/graphql";

const ECOSYSTEM_MAP: Record<string, string> = {
  npm: "NPM",
  pip: "PIP",
  go: "GO",
  maven: "MAVEN",
  cargo: "RUST",
  nuget: "NUGET",
  gem: "RUBYGEMS",
  composer: "COMPOSER",
};

interface GHSAOptions {
  token?: string;
  timeout?: number;
}

interface GHSANode {
  ghsaId: string;
  summary: string;
  description: string;
  severity: string;
  publishedAt: string;
  updatedAt: string;
  permalink: string;
  identifiers: Array<{ type: string; value: string }>;
  references: Array<{ url: string }>;
  cwes: { nodes: Array<{ cweId: string }> };
  vulnerabilities: {
    nodes: Array<{
      package: { name: string; ecosystem: string };
      vulnerableVersionRange: string;
      firstPatchedVersion?: { identifier: string };
    }>;
  };
}

export async function queryGHSA(
  packageName: string,
  ecosystem: Ecosystem,
  options: GHSAOptions = {}
): Promise<Vulnerability[]> {
  const token = options.token || process.env.GITHUB_TOKEN;
  if (!token) return []; // GHSA requires authentication

  const ghEcosystem = ECOSYSTEM_MAP[ecosystem];
  if (!ghEcosystem) return [];

  const query = `
    query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
      securityVulnerabilities(
        first: 25,
        ecosystem: $ecosystem,
        package: $package,
        orderBy: { field: UPDATED_AT, direction: DESC }
      ) {
        nodes {
          advisory {
            ghsaId
            summary
            description
            severity
            publishedAt
            updatedAt
            permalink
            identifiers { type value }
            references { url }
            cwes(first: 5) { nodes { cweId } }
          }
          package { name ecosystem }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
  `;

  try {
    const res = await fetch(GITHUB_API, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query,
        variables: { ecosystem: ghEcosystem, package: packageName },
      }),
      signal: AbortSignal.timeout(options.timeout || 10000),
    });

    if (!res.ok) return [];

    const data = await res.json() as any;
    const nodes = data?.data?.securityVulnerabilities?.nodes || [];

    return nodes.map((node: any) => convertGHSAVuln(node));
  } catch {
    return [];
  }
}

export async function queryGHSABatch(
  packages: Array<{ name: string; ecosystem: Ecosystem }>,
  options: GHSAOptions = {}
): Promise<Map<string, Vulnerability[]>> {
  const results = new Map<string, Vulnerability[]>();
  const token = options.token || process.env.GITHUB_TOKEN;
  if (!token) return results;

  // GHSA doesn't support batch — query sequentially with concurrency limit
  const CONCURRENCY = 5;
  for (let i = 0; i < packages.length; i += CONCURRENCY) {
    const batch = packages.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(
      batch.map(async (pkg) => {
        const vulns = await queryGHSA(pkg.name, pkg.ecosystem, options);
        return { key: `${pkg.ecosystem}:${pkg.name}`, vulns };
      })
    );

    for (const { key, vulns } of batchResults) {
      if (vulns.length > 0) {
        results.set(key, vulns);
      }
    }
  }

  return results;
}

function convertGHSAVuln(node: any): Vulnerability {
  const advisory = node.advisory as GHSANode;

  const aliases: string[] = [];
  for (const id of advisory.identifiers || []) {
    if (id.type === "CVE") aliases.push(id.value);
  }

  const severity = mapGHSASeverity(advisory.severity);

  return {
    id: advisory.ghsaId,
    aliases,
    summary: advisory.summary || "No summary",
    details: advisory.description || "",
    severity,
    affected_versions: node.vulnerableVersionRange || "unknown",
    fixed_version: node.firstPatchedVersion?.identifier,
    references: [
      advisory.permalink,
      ...(advisory.references || []).map((r: any) => r.url),
    ],
    published: advisory.publishedAt,
    modified: advisory.updatedAt,
    source: "ghsa",
    cwes: (advisory.cwes?.nodes || []).map((c: any) => c.cweId),
  };
}

function mapGHSASeverity(severity: string): Severity {
  switch (severity?.toUpperCase()) {
    case "CRITICAL": return "CRITICAL";
    case "HIGH": return "HIGH";
    case "MODERATE": return "MEDIUM";
    case "LOW": return "LOW";
    default: return "UNKNOWN";
  }
}
