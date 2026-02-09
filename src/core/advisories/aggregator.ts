// ─── Vulnerability aggregator ───
// Merges OSV, NVD, GHSA, KEV, EPSS into a unified vuln map.

import type { Dependency, Vulnerability, VulnerabilitySource } from "../../types.js";
import { queryVulnerabilities as queryOSV } from "./osv.js";

const DEFAULT_SOURCES: VulnerabilitySource[] = ["osv", "kev", "epss"];

export async function queryAllSources(
  deps: Dependency[],
  options: { sources?: VulnerabilitySource[]; nvdApiKey?: string; githubToken?: string; } = {}
): Promise<{ vulnMap: Map<string, Vulnerability[]>; sourceTimestamps: Record<string, string> }> {
  const sources = options.sources || DEFAULT_SOURCES;
  const sourceTimestamps: Record<string, string> = {};
  const now = new Date().toISOString();

  // Step 1: OSV (always)
  let vulnMap = new Map<string, Vulnerability[]>();
  if (sources.includes("osv")) {
    vulnMap = await queryOSV(deps);
    sourceTimestamps["osv"] = now;
  }

  // Step 2: GHSA (optional, needs token) - dynamic import
  if (sources.includes("ghsa") && (options.githubToken || process.env.GITHUB_TOKEN)) {
    try {
      const { queryGHSABatch } = await import("../../enrichment/advisories/ghsa.js");
      const packagesToQuery = deps.filter(d => d.isDirect).map(d => ({ name: d.name, ecosystem: d.ecosystem }));
      if (packagesToQuery.length > 0) {
        const ghsaResults = await queryGHSABatch(packagesToQuery, { token: options.githubToken });
        for (const [key, ghsaVulns] of ghsaResults) {
          const dep = deps.find(d => `${d.ecosystem}:${d.name}` === key);
          if (!dep) continue;
          const depKey = `${dep.ecosystem}:${dep.name}@${dep.version}`;
          const existing = vulnMap.get(depKey) || [];
          const existingIds = new Set(existing.flatMap(v => [v.id, ...v.aliases]));
          for (const ghsaVuln of ghsaVulns) {
            const isDuplicate = existingIds.has(ghsaVuln.id) || ghsaVuln.aliases.some(a => existingIds.has(a));
            if (!isDuplicate) existing.push(ghsaVuln);
          }
          if (existing.length > 0) vulnMap.set(depKey, existing);
        }
        sourceTimestamps["ghsa"] = now;
      }
    } catch { /* GHSA is supplementary */ }
  }

  // Step 3: NVD (optional, needs API key) - dynamic import
  if (sources.includes("nvd") && options.nvdApiKey) {
    try {
      const { queryNVD } = await import("../../enrichment/advisories/nvd.js");
      const cveIdsToEnrich: string[] = [];
      for (const vulns of vulnMap.values()) {
        for (const vuln of vulns) {
          if (!vuln.score) {
            const cves = [vuln.id, ...vuln.aliases].filter(id => id.startsWith("CVE-"));
            cveIdsToEnrich.push(...cves);
          }
        }
      }
      if (cveIdsToEnrich.length > 0) {
        const uniqueCves = [...new Set(cveIdsToEnrich)].slice(0, 50);
        const nvdData = await queryNVD(uniqueCves, { apiKey: options.nvdApiKey });
        for (const vulns of vulnMap.values()) {
          for (const vuln of vulns) {
            const cveIds = [vuln.id, ...vuln.aliases].filter(id => id.startsWith("CVE-"));
            for (const cveId of cveIds) {
              const nvdVuln = nvdData.get(cveId);
              if (nvdVuln) {
                if (!vuln.score && nvdVuln.score) { vuln.score = nvdVuln.score; vuln.cvssVector = nvdVuln.cvssVector; vuln.severity = nvdVuln.severity; }
                if (!vuln.cwes?.length && nvdVuln.cwes?.length) vuln.cwes = nvdVuln.cwes;
                break;
              }
            }
          }
        }
        sourceTimestamps["nvd"] = now;
      }
    } catch { /* NVD is supplementary */ }
  }

  // Step 4: KEV (free, default) - dynamic import
  if (sources.includes("kev")) {
    try {
      const { enrichWithKEV } = await import("../../enrichment/advisories/kev.js");
      const allVulns: Vulnerability[] = [];
      for (const vulns of vulnMap.values()) allVulns.push(...vulns);
      await enrichWithKEV(allVulns);
      sourceTimestamps["kev"] = now;
    } catch { /* KEV is supplementary */ }
  }

  // Step 5: EPSS (free, default) - dynamic import
  if (sources.includes("epss")) {
    try {
      const { enrichWithEPSS } = await import("../../enrichment/advisories/epss.js");
      const allVulns: Vulnerability[] = [];
      for (const vulns of vulnMap.values()) allVulns.push(...vulns);
      await enrichWithEPSS(allVulns);
      sourceTimestamps["epss"] = now;
    } catch { /* EPSS is supplementary */ }
  }

  return { vulnMap, sourceTimestamps };
}
