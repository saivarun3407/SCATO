// ─── Scanner Integration Tests ───
// Tests the full scan pipeline with mocked HTTP and file system

import { describe, test, expect, mock, beforeEach, afterEach } from "bun:test";
import type { ScanReport, OSVBatchResponse, Dependency } from "../src/types.js";

// ═══════════════════════════════════════════
// Mock Setup Helpers
// ═══════════════════════════════════════════

function createOSVResponse(depCount: number, vulnIndices: number[] = []): OSVBatchResponse {
  return {
    results: Array.from({ length: depCount }, (_, i) => {
      if (vulnIndices.includes(i)) {
        return {
          vulns: [
            {
              id: `GHSA-test-${String(i).padStart(4, "0")}`,
              aliases: [`CVE-2024-${String(i).padStart(4, "0")}`],
              summary: `Test vulnerability for dependency ${i}`,
              details: `Detailed description of vulnerability ${i}`,
              severity: [
                { type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8" },
              ],
              affected: [
                {
                  package: { name: `dep-${i}`, ecosystem: "npm" },
                  ranges: [
                    {
                      type: "SEMVER",
                      events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }],
                    },
                  ],
                  versions: ["1.0.0"],
                },
              ],
              references: [{ type: "WEB", url: `https://example.com/vuln/${i}` }],
              published: "2024-01-15T00:00:00Z",
              modified: "2024-02-01T00:00:00Z",
            },
          ],
        };
      }
      return {};
    }),
  };
}

// ═══════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════

describe("scan() integration", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test("scan() returns a valid ScanReport structure", async () => {
    // Mock fetch to return OSV responses
    globalThis.fetch = mock(async (url: string | URL | Request) => {
      const urlStr = typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
      if (urlStr.includes("osv.dev")) {
        return new Response(JSON.stringify({ results: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("{}", { status: 200 });
    }) as typeof fetch;

    // We need to mock discoverDependencies since we are not scanning a real directory
    // Import scanner dynamically after mock is set
    const scannerModule = await import("../src/scanner.js");

    // Use a non-existent path -- discoverDependencies will return empty
    // This tests the empty directory case
    const report = await scannerModule.scan({
      target: "/tmp/nonexistent-test-dir-scato",
    });

    expect(report).toBeDefined();
    expect(report.tool).toBe("scato");
    expect(report.version).toBe("3.0.0");
    expect(report.timestamp).toBeDefined();
    expect(report.scanId).toBeDefined();
  });

  test("empty directory returns empty report with zero counts", async () => {
    globalThis.fetch = mock(async () => {
      return new Response(JSON.stringify({ results: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;

    const { scan } = await import("../src/scanner.js");

    const report = await scan({
      target: "/tmp/nonexistent-test-dir-scato-empty",
    });

    expect(report.totalDependencies).toBe(0);
    expect(report.totalVulnerabilities).toBe(0);
    expect(report.ecosystems).toEqual([]);
    expect(report.results).toEqual([]);
    expect(report.severityCounts.CRITICAL).toBe(0);
    expect(report.severityCounts.HIGH).toBe(0);
    expect(report.severityCounts.MEDIUM).toBe(0);
    expect(report.severityCounts.LOW).toBe(0);
    expect(report.severityCounts.UNKNOWN).toBe(0);
  });

  test("empty report has scan duration", async () => {
    globalThis.fetch = mock(async () => {
      return new Response(JSON.stringify({ results: [] }), {
        status: 200,
      });
    }) as typeof fetch;

    const { scan } = await import("../src/scanner.js");

    const report = await scan({
      target: "/tmp/nonexistent-test-dir-scato-duration",
    });

    expect(report.scanDurationMs).toBeDefined();
    expect(report.scanDurationMs!).toBeGreaterThanOrEqual(0);
  });

  test("empty report has metrics with zero values", async () => {
    globalThis.fetch = mock(async () => {
      return new Response(JSON.stringify({ results: [] }), { status: 200 });
    }) as typeof fetch;

    const { scan } = await import("../src/scanner.js");

    const report = await scan({
      target: "/tmp/nonexistent-dir-metrics",
    });

    expect(report.metrics).toBeDefined();
    expect(report.metrics!.riskScore).toBe(0);
    expect(report.metrics!.riskLevel).toBe("none");
    expect(report.metrics!.kevCount).toBe(0);
    expect(report.metrics!.copyleftCount).toBe(0);
  });

  test("empty report has passing policy result", async () => {
    globalThis.fetch = mock(async () => {
      return new Response(JSON.stringify({ results: [] }), { status: 200 });
    }) as typeof fetch;

    const { scan } = await import("../src/scanner.js");

    const report = await scan({
      target: "/tmp/nonexistent-dir-policy",
    });

    expect(report.policyResult).toBeDefined();
    expect(report.policyResult!.passed).toBe(true);
    expect(report.policyResult!.violations).toHaveLength(0);
  });
});

describe("scan() report validation", () => {
  test("ScanReport has all required fields", () => {
    // This tests the type contract by constructing a minimal valid report
    const report: ScanReport = {
      tool: "scato",
      version: "3.0.0",
      timestamp: new Date().toISOString(),
      target: "/test",
      ecosystems: ["npm"],
      totalDependencies: 0,
      totalVulnerabilities: 0,
      severityCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
      results: [],
    };

    expect(report.tool).toBe("scato");
    expect(report.version).toBe("3.0.0");
    expect(report.severityCounts).toBeDefined();
    expect(Object.keys(report.severityCounts)).toHaveLength(5);
  });

  test("ScanReport severity counts include all severity levels", () => {
    const report: ScanReport = {
      tool: "scato",
      version: "3.0.0",
      timestamp: new Date().toISOString(),
      target: "/test",
      ecosystems: [],
      totalDependencies: 0,
      totalVulnerabilities: 0,
      severityCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 },
      results: [],
    };

    const expectedKeys = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
    for (const key of expectedKeys) {
      expect(report.severityCounts).toHaveProperty(key);
    }
  });

  test("scan ID follows UUID format", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock(async () => {
      return new Response(JSON.stringify({ results: [] }), { status: 200 });
    }) as typeof fetch;

    try {
      const { scan } = await import("../src/scanner.js");
      const report = await scan({
        target: "/tmp/nonexistent-dir-uuid",
      });

      expect(report.scanId).toBeDefined();
      // UUID format: 8-4-4-4-12 hex digits
      expect(report.scanId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe("scan() options", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = mock(async () => {
      return new Response(JSON.stringify({ results: [] }), { status: 200 });
    }) as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test("target is preserved in report", async () => {
    const { scan } = await import("../src/scanner.js");
    const report = await scan({ target: "/my/special/path" });

    expect(report.target).toBe("/my/special/path");
  });

  test("ScanOptions accepts all optional parameters", () => {
    // Type-level test: ensure ScanOptions interface is complete
    const options = {
      target: "/test",
      outputJson: true,
      sbomOutput: "/output/sbom.json",
      sbomFormat: "cyclonedx" as const,
      sarifOutput: "/output/scan.sarif",
      skipLicenses: true,
      skipDev: true,
      ecosystems: ["npm" as const],
      sources: ["osv" as const],
      policyFile: "/policy.json",
      failOn: "HIGH" as const,
      ciMode: false,
      prComment: false,
      checkRun: false,
      cacheDir: "/cache",
      cacheTtlHours: 24,
      offlineMode: false,
    };

    expect(options.target).toBe("/test");
    expect(options.sbomFormat).toBe("cyclonedx");
    expect(options.ecosystems).toContain("npm");
  });
});

describe("emptyReport structure", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = mock(async () => {
      return new Response(JSON.stringify({ results: [] }), { status: 200 });
    }) as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test("emptyReport has correct tool and version", async () => {
    const { scan } = await import("../src/scanner.js");
    const report = await scan({ target: "/nonexistent" });

    expect(report.tool).toBe("scato");
    expect(report.version).toBe("3.0.0");
  });

  test("emptyReport has ISO timestamp", async () => {
    const { scan } = await import("../src/scanner.js");
    const report = await scan({ target: "/nonexistent" });

    expect(report.timestamp).toBeDefined();
    expect(new Date(report.timestamp).getTime()).not.toBeNaN();
  });

  test("emptyReport preserves target path", async () => {
    const { scan } = await import("../src/scanner.js");
    const report = await scan({ target: "/my/project/path" });

    expect(report.target).toBe("/my/project/path");
  });
});
