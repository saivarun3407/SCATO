// ─── CISA Known Exploited Vulnerabilities (KEV) Adapter ───
// Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

import type { Vulnerability, Severity } from "../../types.js";

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

interface KEVCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KEVEntry[];
}

interface KEVEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes: string;
}

// In-memory cache (KEV catalog changes infrequently)
let cachedKEV: KEVCatalog | null = null;
let cacheTimestamp = 0;
const CACHE_TTL = 4 * 60 * 60 * 1000; // 4 hours

export async function loadKEVCatalog(timeout = 15000): Promise<KEVCatalog | null> {
  const now = Date.now();
  if (cachedKEV && now - cacheTimestamp < CACHE_TTL) {
    return cachedKEV;
  }

  try {
    const res = await fetch(KEV_URL, {
      signal: AbortSignal.timeout(timeout),
    });

    if (!res.ok) return cachedKEV;

    cachedKEV = (await res.json()) as KEVCatalog;
    cacheTimestamp = now;
    return cachedKEV;
  } catch {
    return cachedKEV; // Return stale cache on error
  }
}

export async function enrichWithKEV(
  vulnerabilities: Vulnerability[]
): Promise<void> {
  const catalog = await loadKEVCatalog();
  if (!catalog) return;

  // Build lookup map from CVE ID to KEV entry
  const kevMap = new Map<string, KEVEntry>();
  for (const entry of catalog.vulnerabilities) {
    kevMap.set(entry.cveID, entry);
  }

  // Enrich each vulnerability
  for (const vuln of vulnerabilities) {
    // Check the vuln ID itself and all aliases
    const idsToCheck = [vuln.id, ...vuln.aliases];

    for (const id of idsToCheck) {
      const kevEntry = kevMap.get(id);
      if (kevEntry) {
        vuln.isKnownExploited = true;
        vuln.kevDateAdded = kevEntry.dateAdded;
        vuln.kevDueDate = kevEntry.dueDate;
        // KEV vulns are always at least HIGH severity
        if (vuln.severity === "UNKNOWN" || vuln.severity === "LOW" || vuln.severity === "MEDIUM") {
          vuln.severity = "HIGH";
        }
        break;
      }
    }
  }
}

export async function getKEVStats(): Promise<{
  totalCount: number;
  catalogVersion: string;
  dateReleased: string;
} | null> {
  const catalog = await loadKEVCatalog();
  if (!catalog) return null;

  return {
    totalCount: catalog.count,
    catalogVersion: catalog.catalogVersion,
    dateReleased: catalog.dateReleased,
  };
}

export function isInKEV(cveId: string): boolean {
  if (!cachedKEV) return false;
  return cachedKEV.vulnerabilities.some((v) => v.cveID === cveId);
}
