// ─── OSV.dev adapter ───
// Primary vuln source (NVD, GHSA, PyPI, RustSec, Go).

import type {
  Dependency,
  Vulnerability,
  Severity,
  OSVBatchQuery,
  OSVBatchResponse,
  OSVVulnerability,
} from "../../types.js";

const OSV_API = "https://api.osv.dev/v1";
const BATCH_SIZE = 1000;

const ECOSYSTEM_MAP: Record<string, string> = {
  npm: "npm",
  pip: "PyPI",
  go: "Go",
  maven: "Maven",
  cargo: "crates.io",
  nuget: "NuGet",
  gem: "RubyGems",
  composer: "Packagist",
};

export async function queryVulnerabilities(
  deps: Dependency[]
): Promise<Map<string, Vulnerability[]>> {
  const results = new Map<string, Vulnerability[]>();

  for (let i = 0; i < deps.length; i += BATCH_SIZE) {
    const batch = deps.slice(i, i + BATCH_SIZE);
    const query: OSVBatchQuery = {
      queries: batch.map((dep) => ({
        package: {
          name: dep.name,
          ecosystem: ECOSYSTEM_MAP[dep.ecosystem] || dep.ecosystem,
        },
        version: dep.version,
      })),
    };

    try {
      const response = await fetch(`${OSV_API}/querybatch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(query),
      });

      if (!response.ok) {
        console.error(`OSV API error: ${response.status} ${response.statusText}`);
        continue;
      }

      const data = (await response.json()) as OSVBatchResponse;

      // Collect vuln IDs that need detail fetching
      const vulnIdsToFetch: string[] = [];

      for (let j = 0; j < batch.length; j++) {
        const vulnResults = data.results[j];
        if (vulnResults?.vulns) {
          for (const v of vulnResults.vulns) {
            if (!v.summary && !v.details) {
              vulnIdsToFetch.push(v.id);
            }
          }
        }
      }

      // Fetch details for vulns missing summaries (max 20 concurrent)
      const detailCache = new Map<string, OSVVulnerability>();
      const uniqueIds = [...new Set(vulnIdsToFetch)];
      for (let k = 0; k < uniqueIds.length; k += 20) {
        const idBatch = uniqueIds.slice(k, k + 20);
        await Promise.all(
          idBatch.map(async (id) => {
            try {
              const res = await fetch(`${OSV_API}/vulns/${id}`, {
                signal: AbortSignal.timeout(5000),
              });
              if (res.ok) {
                const detail = (await res.json()) as OSVVulnerability;
                detailCache.set(id, detail);
              }
            } catch { /* best effort */ }
          })
        );
      }

      for (let j = 0; j < batch.length; j++) {
        const dep = batch[j];
        const vulnResults = data.results[j];
        const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;

        if (vulnResults?.vulns && vulnResults.vulns.length > 0) {
          const enriched = vulnResults.vulns.map((v) => {
            if ((!v.summary && !v.details) && detailCache.has(v.id)) {
              return convertVuln(detailCache.get(v.id)!);
            }
            return convertVuln(v);
          });
          results.set(key, enriched);
        }
      }
    } catch (err) {
      console.error(`OSV API request failed: ${err}`);
    }
  }

  return results;
}

function convertVuln(osv: OSVVulnerability): Vulnerability {
  let score: number | undefined;
  let severity: Severity = "UNKNOWN";
  let cvssVector: string | undefined;

  for (const s of osv.severity || []) {
    if (s.type === "CVSS_V3" || s.type === "CVSS_V2") {
      cvssVector = s.score;
      const scoreMatch = s.score.match(/(\d+\.?\d*)/);
      if (scoreMatch) {
        score = parseFloat(scoreMatch[1]);
      }
    }
  }

  if (score !== undefined) {
    severity = scoreToseverity(score);
  } else {
    severity = inferSeverityFromId(osv.id);
  }

  let fixedVersion: string | undefined;
  for (const affected of osv.affected || []) {
    for (const range of affected.ranges || []) {
      for (const event of range.events || []) {
        if (event.fixed) {
          fixedVersion = event.fixed;
          break;
        }
      }
    }
  }

  let affectedVersions = "unknown";
  for (const affected of osv.affected || []) {
    for (const range of affected.ranges || []) {
      const introduced = range.events?.find((e) => e.introduced)?.introduced;
      const fixed = range.events?.find((e) => e.fixed)?.fixed;
      if (introduced && fixed) {
        affectedVersions = `>=${introduced}, <${fixed}`;
      } else if (introduced) {
        affectedVersions = `>=${introduced}`;
      }
    }
  }

  // Extract CWEs from database_specific if available
  const cwes: string[] = [];
  if (osv.database_specific) {
    const cweList = (osv.database_specific as any).cwe_ids;
    if (Array.isArray(cweList)) {
      cwes.push(...cweList);
    }
  }

  return {
    id: osv.id,
    aliases: osv.aliases || [],
    summary: osv.summary || "No summary available",
    details: osv.details || "",
    severity,
    score,
    cvssVector,
    affected_versions: affectedVersions,
    fixed_version: fixedVersion,
    references: (osv.references || []).map((r) => r.url),
    published: osv.published || "",
    modified: osv.modified,
    source: "osv",
    cwes: cwes.length > 0 ? cwes : undefined,
  };
}

function scoreToseverity(score: number): Severity {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score > 0) return "LOW";
  return "UNKNOWN";
}

function inferSeverityFromId(id: string): Severity {
  if (id.startsWith("GHSA-")) return "MEDIUM";
  return "UNKNOWN";
}
