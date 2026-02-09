// ─── SPDX SBOM Generator Tests ───
// Tests SPDX 2.3 document generation

import { describe, test, expect } from "bun:test";
import { generateSPDX } from "../../src/sbom/spdx.js";
import type { ScanResult } from "../../src/types.js";

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
      },
      vulnerabilities: [
        {
          id: "CVE-2024-1234",
          aliases: ["GHSA-abcd-efgh-ijkl"],
          summary: "Prototype pollution in express",
          details: "A prototype pollution vulnerability.",
          severity: "CRITICAL",
          score: 9.8,
          affected_versions: ">=4.0.0, <4.18.0",
          fixed_version: "4.18.0",
          references: [],
          published: "2024-01-15T00:00:00Z",
          source: "osv",
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
      vulnerabilities: [],
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
  ];
}

// ═══════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════

describe("generateSPDX", () => {
  describe("document structure", () => {
    test("generates valid SPDX 2.3 document", () => {
      const doc = generateSPDX("test-project", createMockResults());

      expect(doc.spdxVersion).toBe("SPDX-2.3");
      expect(doc.dataLicense).toBe("CC0-1.0");
      expect(doc.SPDXID).toBe("SPDXRef-DOCUMENT");
    });

    test("includes project name in document name", () => {
      const doc = generateSPDX("my-web-app", createMockResults());

      expect(doc.name).toContain("my-web-app");
    });

    test("generates unique document namespace", () => {
      const doc1 = generateSPDX("project-1", []);
      const doc2 = generateSPDX("project-2", []);

      expect(doc1.documentNamespace).not.toBe(doc2.documentNamespace);
      expect(doc1.documentNamespace).toContain("scato.dev");
      expect(doc1.documentNamespace).toContain("project-1");
    });

    test("includes creation info with timestamp", () => {
      const doc = generateSPDX("test-project", createMockResults());

      expect(doc.creationInfo).toBeDefined();
      expect(doc.creationInfo.created).toBeDefined();
      expect(new Date(doc.creationInfo.created).getTime()).not.toBeNaN();
    });

    test("includes tool and organization in creators", () => {
      const doc = generateSPDX("test-project", createMockResults());

      expect(doc.creationInfo.creators).toBeDefined();
      expect(doc.creationInfo.creators.length).toBeGreaterThan(0);

      const hasToolCreator = doc.creationInfo.creators.some((c) =>
        c.startsWith("Tool:")
      );
      expect(hasToolCreator).toBe(true);
    });

    test("includes license list version", () => {
      const doc = generateSPDX("test-project", createMockResults());

      expect(doc.creationInfo.licenseListVersion).toBeDefined();
    });
  });

  describe("packages", () => {
    test("includes root package plus all dependencies", () => {
      const results = createMockResults();
      const doc = generateSPDX("test-project", results);

      // Root package + 3 dependencies
      expect(doc.packages).toHaveLength(results.length + 1);
    });

    test("root package has correct structure", () => {
      const doc = generateSPDX("test-project", createMockResults());

      const rootPkg = doc.packages.find(
        (p) => p.SPDXID === "SPDXRef-RootPackage"
      );
      expect(rootPkg).toBeDefined();
      expect(rootPkg!.name).toBe("test-project");
      expect(rootPkg!.primaryPackagePurpose).toBe("APPLICATION");
      expect(rootPkg!.filesAnalyzed).toBe(false);
    });

    test("dependency packages have correct names and versions", () => {
      const doc = generateSPDX("test-project", createMockResults());

      const expressPkg = doc.packages.find((p) => p.name === "express");
      expect(expressPkg).toBeDefined();
      expect(expressPkg!.versionInfo).toBe("4.17.1");

      const lodashPkg = doc.packages.find((p) => p.name === "lodash");
      expect(lodashPkg).toBeDefined();
      expect(lodashPkg!.versionInfo).toBe("4.17.20");
    });

    test("includes PURL in external references", () => {
      const doc = generateSPDX("test-project", createMockResults());

      const expressPkg = doc.packages.find((p) => p.name === "express");
      const purlRef = expressPkg?.externalRefs.find(
        (r) => r.referenceType === "purl"
      );
      expect(purlRef).toBeDefined();
      expect(purlRef!.referenceCategory).toBe("PACKAGE-MANAGER");
      expect(purlRef!.referenceLocator).toContain("pkg:");
    });

    test("uses provided PURL when available", () => {
      const doc = generateSPDX("test-project", createMockResults());

      const expressPkg = doc.packages.find((p) => p.name === "express");
      const purlRef = expressPkg?.externalRefs.find(
        (r) => r.referenceType === "purl"
      );
      expect(purlRef!.referenceLocator).toBe("pkg:npm/express@4.17.1");
    });

    test("generates PURL for packages without one", () => {
      const doc = generateSPDX("test-project", createMockResults());

      const debugPkg = doc.packages.find((p) => p.name === "debug");
      const purlRef = debugPkg?.externalRefs.find(
        (r) => r.referenceType === "purl"
      );
      expect(purlRef).toBeDefined();
      expect(purlRef!.referenceLocator).toContain("pkg:npm/debug@4.3.4");
    });

    test("includes license information when available", () => {
      const doc = generateSPDX("test-project", createMockResults());

      const expressPkg = doc.packages.find((p) => p.name === "express");
      expect(expressPkg!.licenseConcluded).toBe("MIT");
      expect(expressPkg!.licenseDeclared).toBe("MIT");
    });

    test("uses NOASSERTION for packages without license", () => {
      const doc = generateSPDX("test-project", createMockResults());

      const debugPkg = doc.packages.find((p) => p.name === "debug");
      expect(debugPkg!.licenseConcluded).toBe("NOASSERTION");
      expect(debugPkg!.licenseDeclared).toBe("NOASSERTION");
    });

    test("includes download location", () => {
      const doc = generateSPDX("test-project", createMockResults());

      const expressPkg = doc.packages.find((p) => p.name === "express");
      expect(expressPkg!.downloadLocation).toContain("npmjs.org");
    });

    test("includes security external refs for vulnerabilities", () => {
      const doc = generateSPDX("test-project", createMockResults());

      const expressPkg = doc.packages.find((p) => p.name === "express");
      const securityRefs = expressPkg?.externalRefs.filter(
        (r) => r.referenceCategory === "SECURITY"
      );
      expect(securityRefs).toBeDefined();
      expect(securityRefs!.length).toBeGreaterThan(0);
      expect(securityRefs![0].referenceLocator).toBe("CVE-2024-1234");
    });

    test("CVE references use 'cve' type", () => {
      const doc = generateSPDX("test-project", createMockResults());

      const expressPkg = doc.packages.find((p) => p.name === "express");
      const cveRef = expressPkg?.externalRefs.find(
        (r) => r.referenceLocator === "CVE-2024-1234"
      );
      expect(cveRef!.referenceType).toBe("cve");
    });

    test("includes supplier for scoped npm packages", () => {
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
      const doc = generateSPDX("angular-app", results);

      const angularPkg = doc.packages.find((p) => p.name === "@angular/core");
      expect(angularPkg?.supplier).toContain("angular");
    });

    test("all packages have filesAnalyzed set to false", () => {
      const doc = generateSPDX("test-project", createMockResults());

      for (const pkg of doc.packages) {
        expect(pkg.filesAnalyzed).toBe(false);
      }
    });
  });

  describe("relationships", () => {
    test("includes DESCRIBES relationship from document to root", () => {
      const doc = generateSPDX("test-project", createMockResults());

      const describesRel = doc.relationships.find(
        (r) => r.relationshipType === "DESCRIBES"
      );
      expect(describesRel).toBeDefined();
      expect(describesRel!.spdxElementId).toBe("SPDXRef-DOCUMENT");
      expect(describesRel!.relatedSpdxElement).toBe("SPDXRef-RootPackage");
    });

    test("direct dependencies have DEPENDS_ON relationship", () => {
      const doc = generateSPDX("test-project", createMockResults());

      const dependsOnRels = doc.relationships.filter(
        (r) =>
          r.relationshipType === "DEPENDS_ON" &&
          r.spdxElementId === "SPDXRef-RootPackage"
      );
      expect(dependsOnRels.length).toBe(2); // express and lodash
    });

    test("transitive dependencies have DEPENDENCY_OF relationship", () => {
      const doc = generateSPDX("test-project", createMockResults());

      const transitiveRels = doc.relationships.filter(
        (r) =>
          r.relationshipType === "DEPENDENCY_OF" &&
          r.spdxElementId !== "SPDXRef-RootPackage"
      );
      // debug is transitive with parent express
      expect(transitiveRels.length).toBeGreaterThan(0);
    });

    test("relationship count matches dependencies plus document relationship", () => {
      const results = createMockResults();
      const doc = generateSPDX("test-project", results);

      // At minimum: 1 DESCRIBES + 1 per dependency
      expect(doc.relationships.length).toBeGreaterThanOrEqual(
        results.length + 1
      );
    });
  });

  describe("multi-ecosystem support", () => {
    test("generates correct PURLs for different ecosystems", () => {
      const results: ScanResult[] = [
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

      const doc = generateSPDX("multi-eco", results);

      const requestsPkg = doc.packages.find((p) => p.name === "requests");
      const purlRef = requestsPkg?.externalRefs.find(
        (r) => r.referenceType === "purl"
      );
      expect(purlRef!.referenceLocator).toContain("pkg:pypi/");

      const serdePkg = doc.packages.find((p) => p.name === "serde");
      const cargoRef = serdePkg?.externalRefs.find(
        (r) => r.referenceType === "purl"
      );
      expect(cargoRef!.referenceLocator).toContain("pkg:cargo/");
    });

    test("generates correct download locations for different ecosystems", () => {
      const results: ScanResult[] = [
        {
          dependency: {
            name: "requests",
            version: "2.28.0",
            ecosystem: "pip",
            isDirect: true,
          },
          vulnerabilities: [],
        },
      ];

      const doc = generateSPDX("pypi-test", results);
      const requestsPkg = doc.packages.find((p) => p.name === "requests");
      expect(requestsPkg!.downloadLocation).toContain("pypi.org");
    });
  });

  describe("edge cases", () => {
    test("handles empty results array", () => {
      const doc = generateSPDX("empty-project", []);

      // Should still have root package
      expect(doc.packages).toHaveLength(1);
      expect(doc.relationships).toHaveLength(1); // DESCRIBES only
    });

    test("sanitizes SPDX IDs for special characters", () => {
      const results: ScanResult[] = [
        {
          dependency: {
            name: "@scope/pkg-name",
            version: "1.0.0-beta.1",
            ecosystem: "npm",
            isDirect: true,
          },
          vulnerabilities: [],
        },
      ];

      const doc = generateSPDX("test", results);
      const pkg = doc.packages.find((p) => p.name === "@scope/pkg-name");
      // SPDXID should not contain invalid characters like @ or /
      expect(pkg!.SPDXID).not.toMatch(/[@\/]/);
    });

    test("handles Maven group:artifact naming", () => {
      const results: ScanResult[] = [
        {
          dependency: {
            name: "org.apache.commons:commons-lang3",
            version: "3.12.0",
            ecosystem: "maven",
            isDirect: true,
          },
          vulnerabilities: [],
        },
      ];

      const doc = generateSPDX("java-project", results);
      const mavenPkg = doc.packages.find((p) =>
        p.name.includes("commons-lang3")
      );
      expect(mavenPkg).toBeDefined();
      expect(mavenPkg!.supplier).toContain("org.apache.commons");
    });
  });
});
