// ─── Vulnerability Aggregator Tests ───
// Tests the aggregator's queryAllSources function with mocked OSV HTTP calls

import { describe, test, expect, mock, beforeEach, afterEach } from "bun:test";
import type { Dependency, Vulnerability, OSVBatchResponse } from "../../../src/types.js";

// ═══════════════════════════════════════════
// Mock Data
// ═══════════════════════════════════════════

function createMockDeps(): Dependency[] {
  return [
    {
      name: "express",
      version: "4.17.1",
      ecosystem: "npm",
      isDirect: true,
      purl: "pkg:npm/express@4.17.1",
    },
    {
      name: "lodash",
      version: "4.17.20",
      ecosystem: "npm",
      isDirect: true,
      purl: "pkg:npm/lodash@4.17.20",
    },
    {
      name: "debug",
      version: "4.3.4",
      ecosystem: "npm",
      isDirect: false,
      parent: "express",
    },
  ];
}

function createOSVBatchResponse(): OSVBatchResponse {
  return {
    results: [
      {
        vulns: [
          {
            id: "GHSA-abcd-efgh-0001",
            aliases: ["CVE-2024-1234"],
            summary: "Prototype pollution in express",
            details: "A prototype pollution vulnerability.",
            severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8" }],
            affected: [
              {
                package: { name: "express", ecosystem: "npm" },
                ranges: [
                  {
                    type: "SEMVER",
                    events: [{ introduced: "4.0.0" }, { fixed: "4.18.0" }],
                  },
                ],
                versions: ["4.17.1"],
              },
            ],
            references: [{ type: "WEB", url: "https://example.com/advisory/1" }],
            published: "2024-01-15T00:00:00Z",
            modified: "2024-02-01T00:00:00Z",
            database_specific: { cwe_ids: ["CWE-1321"] },
          },
        ],
      },
      {
        vulns: [
          {
            id: "GHSA-wxyz-9876-5432",
            aliases: ["CVE-2024-5678"],
            summary: "ReDoS in lodash",
            details: "Regular expression denial of service.",
            severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/7.5" }],
            affected: [
              {
                package: { name: "lodash", ecosystem: "npm" },
                ranges: [
                  {
                    type: "SEMVER",
                    events: [{ introduced: "4.0.0" }, { fixed: "4.17.21" }],
                  },
                ],
                versions: ["4.17.20"],
              },
            ],
            references: [{ type: "WEB", url: "https://example.com/advisory/2" }],
            published: "2024-03-10T00:00:00Z",
            modified: "2024-04-01T00:00:00Z",
          },
        ],
      },
      {
        // debug has no vulns
      },
    ],
  };
}

function createEmptyOSVResponse(count: number): OSVBatchResponse {
  return {
    results: Array.from({ length: count }, () => ({})),
  };
}

// ═══════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════

describe("queryAllSources", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test("returns vulnMap with correct keys for vulnerable dependencies", async () => {
    const mockResponse = createOSVBatchResponse();

    globalThis.fetch = mock(async (url: string | URL | Request) => {
      const urlStr = typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
      if (urlStr.includes("/querybatch")) {
        return new Response(JSON.stringify(mockResponse), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("{}", { status: 200 });
    }) as typeof fetch;

    const { queryAllSources } = await import("../../../src/core/advisories/aggregator.js");
    const deps = createMockDeps();
    const { vulnMap } = await queryAllSources(deps, { sources: ["osv"] });

    // Express should have a vulnerability
    const expressKey = "npm:express@4.17.1";
    expect(vulnMap.has(expressKey)).toBe(true);
    expect(vulnMap.get(expressKey)!.length).toBeGreaterThan(0);

    // Lodash should have a vulnerability
    const lodashKey = "npm:lodash@4.17.20";
    expect(vulnMap.has(lodashKey)).toBe(true);
    expect(vulnMap.get(lodashKey)!.length).toBeGreaterThan(0);

    // Debug should not have vulnerabilities
    const debugKey = "npm:debug@4.3.4";
    expect(vulnMap.has(debugKey)).toBe(false);
  });

  test("returns correct vulnerability details from OSV response", async () => {
    const mockResponse = createOSVBatchResponse();

    globalThis.fetch = mock(async (url: string | URL | Request) => {
      const urlStr = typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
      if (urlStr.includes("/querybatch")) {
        return new Response(JSON.stringify(mockResponse), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("{}", { status: 200 });
    }) as typeof fetch;

    const { queryAllSources } = await import("../../../src/core/advisories/aggregator.js");
    const deps = createMockDeps();
    const { vulnMap } = await queryAllSources(deps, { sources: ["osv"] });

    const expressVulns = vulnMap.get("npm:express@4.17.1")!;
    expect(expressVulns[0].id).toBe("GHSA-abcd-efgh-0001");
    expect(expressVulns[0].source).toBe("osv");
    expect(expressVulns[0].fixed_version).toBe("4.18.0");
  });

  test("handles empty dependency list", async () => {
    globalThis.fetch = mock(async () => {
      return new Response(JSON.stringify({ results: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;

    const { queryAllSources } = await import("../../../src/core/advisories/aggregator.js");
    const { vulnMap } = await queryAllSources([], { sources: ["osv"] });

    expect(vulnMap.size).toBe(0);
  });

  test("returns source timestamps", async () => {
    const mockResponse = createEmptyOSVResponse(1);

    globalThis.fetch = mock(async () => {
      return new Response(JSON.stringify(mockResponse), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;

    const { queryAllSources } = await import("../../../src/core/advisories/aggregator.js");
    const deps: Dependency[] = [
      { name: "test-pkg", version: "1.0.0", ecosystem: "npm", isDirect: true },
    ];
    const { sourceTimestamps } = await queryAllSources(deps, { sources: ["osv"] });

    expect(sourceTimestamps["osv"]).toBeDefined();
    // Timestamp should be a valid ISO date string
    expect(new Date(sourceTimestamps["osv"]).getTime()).not.toBeNaN();
  });

  test("handles OSV API errors gracefully", async () => {
    globalThis.fetch = mock(async () => {
      return new Response("Internal Server Error", { status: 500 });
    }) as typeof fetch;

    const { queryAllSources } = await import("../../../src/core/advisories/aggregator.js");
    const deps = createMockDeps();
    const { vulnMap } = await queryAllSources(deps, { sources: ["osv"] });

    // Should return empty map on API error, not throw
    expect(vulnMap.size).toBe(0);
  });

  test("handles network failures gracefully", async () => {
    globalThis.fetch = mock(async () => {
      throw new Error("Network error");
    }) as typeof fetch;

    const { queryAllSources } = await import("../../../src/core/advisories/aggregator.js");
    const deps = createMockDeps();
    const { vulnMap } = await queryAllSources(deps, { sources: ["osv"] });

    expect(vulnMap.size).toBe(0);
  });

  test("only queries requested sources", async () => {
    let fetchCallUrls: string[] = [];

    globalThis.fetch = mock(async (url: string | URL | Request) => {
      const urlStr = typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
      fetchCallUrls.push(urlStr);
      if (urlStr.includes("/querybatch")) {
        return new Response(JSON.stringify(createEmptyOSVResponse(3)), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("{}", { status: 200 });
    }) as typeof fetch;

    const { queryAllSources } = await import("../../../src/core/advisories/aggregator.js");
    const deps = createMockDeps();

    // Only request OSV, skip kev/epss
    await queryAllSources(deps, { sources: ["osv"] });

    // Should have called OSV querybatch
    const osvCalls = fetchCallUrls.filter((u) => u.includes("osv.dev"));
    expect(osvCalls.length).toBeGreaterThan(0);
  });

  test("handles dependencies with no vulnerabilities", async () => {
    const emptyResponse = createEmptyOSVResponse(3);

    globalThis.fetch = mock(async () => {
      return new Response(JSON.stringify(emptyResponse), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;

    const { queryAllSources } = await import("../../../src/core/advisories/aggregator.js");
    const deps = createMockDeps();
    const { vulnMap } = await queryAllSources(deps, { sources: ["osv"] });

    // No vulnerabilities found
    expect(vulnMap.size).toBe(0);
  });
});
