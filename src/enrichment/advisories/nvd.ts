// ─── NVD (National Vulnerability Database) Adapter ───
// Uses NVD 2.0 API: https://services.nvd.nist.gov/rest/json/cves/2.0

import type { Vulnerability, Severity } from "../../types.js";

const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const RATE_LIMIT_MS = 6000; // 6s between requests without API key, 0.6s with key

interface NVDOptions {
  apiKey?: string;
  timeout?: number;
}

interface NVDResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities: Array<{
    cve: NVDCve;
  }>;
}

interface NVDCve {
  id: string;
  published: string;
  lastModified: string;
  descriptions: Array<{ lang: string; value: string }>;
  metrics?: {
    cvssMetricV31?: Array<{
      cvssData: {
        baseScore: number;
        baseSeverity: string;
        vectorString: string;
      };
    }>;
    cvssMetricV2?: Array<{
      cvssData: {
        baseScore: number;
        vectorString: string;
      };
    }>;
  };
  weaknesses?: Array<{
    description: Array<{ lang: string; value: string }>;
  }>;
  references?: Array<{
    url: string;
    source: string;
  }>;
}

let lastRequestTime = 0;

async function rateLimitedFetch(url: string, options: NVDOptions): Promise<Response> {
  const delay = options.apiKey ? 600 : RATE_LIMIT_MS;
  const now = Date.now();
  const timeSinceLast = now - lastRequestTime;

  if (timeSinceLast < delay) {
    await new Promise((resolve) => setTimeout(resolve, delay - timeSinceLast));
  }

  lastRequestTime = Date.now();

  const headers: Record<string, string> = {
    "Accept": "application/json",
  };
  if (options.apiKey) {
    headers["apiKey"] = options.apiKey;
  }

  return fetch(url, {
    headers,
    signal: AbortSignal.timeout(options.timeout || 15000),
  });
}

export async function queryNVD(
  cveIds: string[],
  options: NVDOptions = {}
): Promise<Map<string, Vulnerability>> {
  const results = new Map<string, Vulnerability>();

  // NVD only accepts CVE IDs
  const validCveIds = cveIds.filter((id) => id.startsWith("CVE-"));
  if (validCveIds.length === 0) return results;

  // Query one at a time (NVD rate limits are strict)
  for (const cveId of validCveIds) {
    try {
      const url = `${NVD_API}?cveId=${encodeURIComponent(cveId)}`;
      const res = await rateLimitedFetch(url, options);

      if (!res.ok) {
        if (res.status === 403 || res.status === 429) {
          // Rate limited — wait and skip
          await new Promise((r) => setTimeout(r, 30000));
          continue;
        }
        continue;
      }

      const data = (await res.json()) as NVDResponse;
      if (data.vulnerabilities?.length > 0) {
        const vuln = convertNVDVuln(data.vulnerabilities[0].cve);
        results.set(cveId, vuln);
      }
    } catch {
      // Best effort — NVD can be slow/unreliable
    }
  }

  return results;
}

export async function searchNVDByKeyword(
  keyword: string,
  options: NVDOptions = {}
): Promise<Vulnerability[]> {
  try {
    const url = `${NVD_API}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=20`;
    const res = await rateLimitedFetch(url, options);

    if (!res.ok) return [];

    const data = (await res.json()) as NVDResponse;
    return (data.vulnerabilities || []).map((v) => convertNVDVuln(v.cve));
  } catch {
    return [];
  }
}

function convertNVDVuln(cve: NVDCve): Vulnerability {
  let score: number | undefined;
  let severity: Severity = "UNKNOWN";
  let cvssVector: string | undefined;

  // Prefer CVSS v3.1
  const v31 = cve.metrics?.cvssMetricV31?.[0];
  if (v31) {
    score = v31.cvssData.baseScore;
    severity = mapNVDSeverity(v31.cvssData.baseSeverity);
    cvssVector = v31.cvssData.vectorString;
  } else {
    const v2 = cve.metrics?.cvssMetricV2?.[0];
    if (v2) {
      score = v2.cvssData.baseScore;
      severity = scoreToseverity(v2.cvssData.baseScore);
      cvssVector = v2.cvssData.vectorString;
    }
  }

  const description =
    cve.descriptions?.find((d) => d.lang === "en")?.value || "No description available";

  const cwes: string[] = [];
  for (const weakness of cve.weaknesses || []) {
    for (const desc of weakness.description || []) {
      if (desc.value && desc.value !== "NVD-CWE-noinfo" && desc.value !== "NVD-CWE-Other") {
        cwes.push(desc.value);
      }
    }
  }

  return {
    id: cve.id,
    aliases: [],
    summary: description.slice(0, 500),
    details: description,
    severity,
    score,
    cvssVector,
    affected_versions: "See NVD for details",
    references: (cve.references || []).map((r) => r.url),
    published: cve.published,
    modified: cve.lastModified,
    source: "nvd",
    cwes,
  };
}

function mapNVDSeverity(baseSeverity: string): Severity {
  switch (baseSeverity.toUpperCase()) {
    case "CRITICAL": return "CRITICAL";
    case "HIGH": return "HIGH";
    case "MEDIUM": return "MEDIUM";
    case "LOW": return "LOW";
    default: return "UNKNOWN";
  }
}

function scoreToseverity(score: number): Severity {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score > 0) return "LOW";
  return "UNKNOWN";
}
