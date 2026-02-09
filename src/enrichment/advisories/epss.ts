// ─── EPSS (Exploit Prediction Scoring System) Adapter ───
// API: https://api.first.org/data/v1/epss

import type { Vulnerability } from "../../types.js";

const EPSS_API = "https://api.first.org/data/v1/epss";

interface EPSSResponse {
  status: string;
  "status-code": number;
  version: string;
  total: number;
  data: EPSSEntry[];
}

interface EPSSEntry {
  cve: string;
  epss: string; // float as string
  percentile: string; // float as string
  date: string;
}

export async function queryEPSS(
  cveIds: string[],
  timeout = 10000
): Promise<Map<string, { score: number; percentile: number }>> {
  const results = new Map<string, { score: number; percentile: number }>();

  // Filter to valid CVE IDs only
  const validIds = cveIds.filter((id) => id.startsWith("CVE-"));
  if (validIds.length === 0) return results;

  // EPSS supports batch queries via comma-separated CVEs
  // Process in batches of 100
  const BATCH_SIZE = 100;

  for (let i = 0; i < validIds.length; i += BATCH_SIZE) {
    const batch = validIds.slice(i, i + BATCH_SIZE);
    const cveParam = batch.join(",");

    try {
      const res = await fetch(`${EPSS_API}?cve=${encodeURIComponent(cveParam)}`, {
        signal: AbortSignal.timeout(timeout),
      });

      if (!res.ok) continue;

      const data = (await res.json()) as EPSSResponse;

      for (const entry of data.data || []) {
        results.set(entry.cve, {
          score: parseFloat(entry.epss),
          percentile: parseFloat(entry.percentile),
        });
      }
    } catch {
      // Best effort — EPSS is supplementary data
    }
  }

  return results;
}

export async function enrichWithEPSS(
  vulnerabilities: Vulnerability[]
): Promise<void> {
  // Collect all CVE IDs from vulnerabilities and their aliases
  const cveIds: string[] = [];
  const vulnByCve = new Map<string, Vulnerability[]>();

  for (const vuln of vulnerabilities) {
    const allIds = [vuln.id, ...vuln.aliases].filter((id) => id.startsWith("CVE-"));
    for (const id of allIds) {
      cveIds.push(id);
      if (!vulnByCve.has(id)) vulnByCve.set(id, []);
      vulnByCve.get(id)!.push(vuln);
    }
  }

  if (cveIds.length === 0) return;

  const epssData = await queryEPSS([...new Set(cveIds)]);

  // Enrich vulnerabilities with EPSS data
  for (const [cveId, data] of epssData) {
    const vulns = vulnByCve.get(cveId) || [];
    for (const vuln of vulns) {
      vuln.epssScore = data.score;
      vuln.epssPercentile = data.percentile;
    }
  }
}
