// ─── CycloneDX SBOM Generator Tests ───
// Tests CycloneDX 1.5 compliant SBOM generation

import { describe, test, expect } from "bun:test";
import { generateSBOM } from "../../src/sbom/cyclonedx.js";
import type { ScanResult, CycloneDXBom } from "../../src/types.js";

// ═══════════════════════════════════════════
// Mock Data
// ═══════════════════════════════════════════

function createMockResults(): ScanResult[] {
  return [
    {
      dependency: {
        name: "express",
        version: "4.17.1",
        ecosystem: "npm",
        isDirect: true,
        license: "MIT",
        purl: "pkg:npm/express@4.17.1",
        scope: "runtime",
      },
      vulnerabilities: [
        {
          id: "CVE-2024-1234",
          aliases: ["GHSA-abcd-efgh-ijkl"],
          summary: "Prototype pollution in express",
          details: "A prototype pollution vulnerability.",
          severity: "CRITICAL",
          score: 9.8,
          cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          affected_versions: ">=4.0.0, <4.18.0",
          fixed_version: "4.18.0",
          references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
          published: "2024-01-15T00:00:00Z",
          source: "osv",
          isKnownExploited: true,
          kevDateAdded: "2024-02-01",
          epssScore: 0.85,
          epssPercentile: 0.97,
          cwes: ["CWE-1321"],
        },
      ],
    },
    {
      dependency: {
        name: "lodash",
        version: "4.17.20",
        ecosystem: "npm",
        isDirect: true,
        license: "MIT",
      },
      vulnerabilities: [
        {
          id: "GHSA-wxyz-9876-5432",
          aliases: [],
          summary: "ReDoS in lodash",
          details: "Regular expression denial of service.",
          severity: "HIGH",
          score: 7.5,
          affected_versions: ">=4.0.0, <4.17.21",
          fixed_version: "4.17.21",
          references: [],
          published: "2024-03-10T00:00:00Z",
          source: "osv",
        },
      ],
    },
    {
      dependency: {
        name: "debug",
        version: "4.3.4",
        ecosystem: "npm",
        isDirect: false,
        parent: "express",
      },
      vulnerabilities: [],
    },
    {
      dependency: {
        name: "ms",
        version: "2.1.3",
        ecosystem: "npm",
        isDirect: false,
        parent: "debug",
      },
      vulnerabilities: [],
    },
  ];
}

function createCleanResults(): ScanResult[] {
  return [
    {
      dependency: {
        name: "react",
        version: "18.2.0",
        ecosystem: "npm",
        isDirect: true,
        license: "MIT",
        purl: "pkg:npm/react@18.2.0",
      },
      vulnerabilities: [],
    },
    {
      dependency: {
        name: "typescript",
        version: "5.6.0",
        ecosystem: "npm",
        isDirect: true,
        license: "Apache-2.0",
        scope: "dev",
      },
      vulnerabilities: [],
    },
  ];
}

// ═══════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════

describe("generateSBOM (CycloneDX)", () => {
  describe("BOM structure", () => {
    test("generates valid BOM format identifier", () => {
      const bom = generateSBOM("test-project", createMockResults());

      expect(bom.bomFormat).toBe("CycloneDX");
      expect(bom.specVersion).toBe("1.5");
      expect(bom.version).toBe(1);
    });

    test("generates unique serial number", () => {
      const bom1 = generateSBOM("project-1", createCleanResults());
      const bom2 = generateSBOM("project-2", createCleanResults());

      expect(bom1.serialNumber).toMatch(/^urn:uuid:/);
      expect(bom2.serialNumber).toMatch(/^urn:uuid:/);
      expect(bom1.serialNumber).not.toBe(bom2.serialNumber);
    });

    test("includes correct metadata", () => {
      const bom = generateSBOM("my-app", createMockResults());

      expect(bom.metadata.timestamp).toBeDefined();
      expect(new Date(bom.metadata.timestamp).getTime()).not.toBeNaN();
      expect(bom.metadata.tools.components).toHaveLength(1);
      expect(bom.metadata.tools.components[0].name).toBe("scato");
      expect(bom.metadata.component?.name).toBe("my-app");
      expect(bom.metadata.component?.type).toBe("application");
    });
  });

  describe("components", () => {
    test("generates components for all dependencies", () => {
      const results = createMockResults();
      const bom = generateSBOM("test-project", results);

      expect(bom.components).toHaveLength(results.length);
    });

    test("includes PURLs for all components", () => {
      const bom = generateSBOM("test-project", createMockResults());

      for (const component of bom.components) {
        expect(component.purl).toBeDefined();
        expect(component.purl).toMatch(/^pkg:/);
      }
    });

    test("uses provided PURL when available", () => {
      const bom = generateSBOM("test-project", createMockResults());

      const expressComp = bom.components.find((c) => c.name === "express");
      expect(expressComp?.purl).toBe("pkg:npm/express@4.17.1");
    });

    test("generates PURL when not provided", () => {
      const bom = generateSBOM("test-project", createMockResults());

      const debugComp = bom.components.find((c) => c.name === "debug");
      expect(debugComp?.purl).toBe("pkg:npm/debug@4.3.4");
    });

    test("includes bom-ref for each component", () => {
      const bom = generateSBOM("test-project", createMockResults());

      for (const component of bom.components) {
        expect(component["bom-ref"]).toBeDefined();
        expect(component["bom-ref"]).toContain(component.name);
      }
    });

    test("includes license information when available", () => {
      const bom = generateSBOM("test-project", createMockResults());

      const expressComp = bom.components.find((c) => c.name === "express");
      expect(expressComp?.licenses).toBeDefined();
      expect(expressComp!.licenses![0].license.id).toBe("MIT");
    });

    test("omits license for components without license data", () => {
      const bom = generateSBOM("test-project", createMockResults());

      const debugComp = bom.components.find((c) => c.name === "debug");
      expect(debugComp?.licenses).toBeUndefined();
    });

    test("sets correct component type", () => {
      const bom = generateSBOM("test-project", createMockResults());

      for (const component of bom.components) {
        expect(component.type).toBe("library");
      }
    });

    test("sets scope based on isDirect", () => {
      const bom = generateSBOM("test-project", createMockResults());

      const expressComp = bom.components.find((c) => c.name === "express");
      expect(expressComp?.scope).toBe("required");

      const debugComp = bom.components.find((c) => c.name === "debug");
      expect(debugComp?.scope).toBe("optional");
    });

    test("includes ecosystem in properties", () => {
      const bom = generateSBOM("test-project", createMockResults());

      const expressComp = bom.components.find((c) => c.name === "express");
      const ecosystemProp = expressComp?.properties?.find(
        (p) => p.name === "scato:ecosystem"
      );
      expect(ecosystemProp?.value).toBe("npm");
    });
  });

  describe("vulnerabilities", () => {
    test("includes vulnerability entries for affected components", () => {
      const bom = generateSBOM("test-project", createMockResults());

      expect(bom.vulnerabilities).toBeDefined();
      expect(bom.vulnerabilities!.length).toBe(2);
    });

    test("vulnerability has correct ID and source", () => {
      const bom = generateSBOM("test-project", createMockResults());

      const cveVuln = bom.vulnerabilities!.find((v) => v.id === "CVE-2024-1234");
      expect(cveVuln).toBeDefined();
      expect(cveVuln!.source.name).toBe("OSV");
      expect(cveVuln!.source.url).toContain("nvd.nist.gov");
    });

    test("vulnerability has correct severity rating", () => {
      const bom = generateSBOM("test-project", createMockResults());

      const cveVuln = bom.vulnerabilities!.find((v) => v.id === "CVE-2024-1234");
      expect(cveVuln!.ratings[0].severity).toBe("critical");
      expect(cveVuln!.ratings[0].score).toBe(9.8);
    });

    test("vulnerability references affected component", () => {
      const bom = generateSBOM("test-project", createMockResults());

      const cveVuln = bom.vulnerabilities!.find((v) => v.id === "CVE-2024-1234");
      expect(cveVuln!.affects).toHaveLength(1);
      expect(cveVuln!.affects[0].ref).toContain("express");
    });

    test("includes CWE references when available", () => {
      const bom = generateSBOM("test-project", createMockResults());

      const cveVuln = bom.vulnerabilities!.find((v) => v.id === "CVE-2024-1234");
      expect(cveVuln!.cwes).toBeDefined();
      expect(cveVuln!.cwes).toContain(1321);
    });

    test("includes EPSS data as properties", () => {
      const bom = generateSBOM("test-project", createMockResults());

      const cveVuln = bom.vulnerabilities!.find((v) => v.id === "CVE-2024-1234");
      const epssProp = cveVuln!.properties?.find(
        (p) => p.name === "scato:epss_score"
      );
      expect(epssProp).toBeDefined();
      expect(epssProp!.value).toBe("0.85");
    });

    test("includes KEV data as properties", () => {
      const bom = generateSBOM("test-project", createMockResults());

      const cveVuln = bom.vulnerabilities!.find((v) => v.id === "CVE-2024-1234");
      const kevProp = cveVuln!.properties?.find(
        (p) => p.name === "scato:kev"
      );
      expect(kevProp).toBeDefined();
      expect(kevProp!.value).toBe("true");
    });

    test("omits vulnerabilities array for clean results", () => {
      const bom = generateSBOM("clean-project", createCleanResults());

      expect(bom.vulnerabilities).toBeUndefined();
    });

    test("GHSA source URL points to GitHub advisories", () => {
      const bom = generateSBOM("test-project", createMockResults());

      const ghsaVuln = bom.vulnerabilities!.find((v) =>
        v.id.startsWith("GHSA-")
      );
      expect(ghsaVuln).toBeDefined();
      expect(ghsaVuln!.source.url).toContain("github.com/advisories");
    });
  });

  describe("dependency graph", () => {
    test("includes dependency graph for components with parents", () => {
      const bom = generateSBOM("test-project", createMockResults());

      expect(bom.dependencies).toBeDefined();
      expect(bom.dependencies!.length).toBeGreaterThan(0);
    });

    test("root dependency lists direct dependencies", () => {
      const bom = generateSBOM("test-project", createMockResults());

      const rootDep = bom.dependencies!.find((d) =>
        d.ref.includes("test-project")
      );
      expect(rootDep).toBeDefined();
      expect(rootDep!.dependsOn).toBeDefined();
      expect(rootDep!.dependsOn!.length).toBe(2); // express and lodash are direct
    });

    test("parent-child relationships are captured", () => {
      const bom = generateSBOM("test-project", createMockResults());

      // express -> debug relationship
      const expressDep = bom.dependencies!.find((d) =>
        d.ref.includes("express@4.17.1")
      );
      if (expressDep) {
        expect(expressDep.dependsOn).toBeDefined();
        const hasDebug = expressDep.dependsOn!.some((d) =>
          d.includes("debug")
        );
        expect(hasDebug).toBe(true);
      }
    });

    test("omits dependency graph when no relationships exist", () => {
      const results: ScanResult[] = [
        {
          dependency: {
            name: "standalone",
            version: "1.0.0",
            ecosystem: "npm",
            isDirect: false, // not direct, so won't be in root deps
          },
          vulnerabilities: [],
        },
      ];
      const bom = generateSBOM("test-project", results);

      // With no direct deps and no parent relationships, dependencies may be empty
      expect(bom.dependencies === undefined || bom.dependencies.length === 0).toBe(true);
    });
  });

  describe("multi-ecosystem support", () => {
    test("handles mixed ecosystem results", () => {
      const results: ScanResult[] = [
        {
          dependency: {
            name: "express",
            version: "4.17.1",
            ecosystem: "npm",
            isDirect: true,
          },
          vulnerabilities: [],
        },
        {
          dependency: {
            name: "requests",
            version: "2.28.0",
            ecosystem: "pip",
            isDirect: true,
          },
          vulnerabilities: [],
        },
        {
          dependency: {
            name: "serde",
            version: "1.0.0",
            ecosystem: "cargo",
            isDirect: true,
          },
          vulnerabilities: [],
        },
      ];

      const bom = generateSBOM("multi-eco", results);
      expect(bom.components).toHaveLength(3);

      const purls = bom.components.map((c) => c.purl);
      expect(purls.some((p) => p.includes("pkg:npm/"))).toBe(true);
      expect(purls.some((p) => p.includes("pkg:pip/"))).toBe(true);
      expect(purls.some((p) => p.includes("pkg:cargo/"))).toBe(true);
    });
  });

  describe("edge cases", () => {
    test("handles empty results array", () => {
      const bom = generateSBOM("empty-project", []);

      expect(bom.components).toHaveLength(0);
      expect(bom.vulnerabilities).toBeUndefined();
    });

    test("handles special characters in package names", () => {
      const results: ScanResult[] = [
        {
          dependency: {
            name: "@angular/core",
            version: "16.0.0",
            ecosystem: "npm",
            isDirect: true,
          },
          vulnerabilities: [],
        },
      ];
      const bom = generateSBOM("angular-app", results);

      expect(bom.components[0].name).toBe("@angular/core");
      expect(bom.components[0].purl).toContain("@angular/core");
    });
  });
});
