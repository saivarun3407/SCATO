// ─── CycloneDX SBOM Generator ───
// Generates CycloneDX 1.5 compliant SBOMs with dependency graph

import { writeFile } from "fs/promises";
import { randomUUID } from "crypto";
import type {
  ScanResult,
  CycloneDXBom,
  CycloneDXComponent,
  CycloneDXDependency,
  CycloneDXVulnerability,
} from "../types.js";

export function generateSBOM(
  projectName: string,
  results: ScanResult[]
): CycloneDXBom {
  const components: CycloneDXComponent[] = [];
  const vulnerabilities: CycloneDXVulnerability[] = [];
  const dependencies: CycloneDXDependency[] = [];

  // Track dependencies for the dependency graph
  const parentMap = new Map<string, Set<string>>();

  for (const result of results) {
    const dep = result.dependency;
    const bomRef = `${dep.ecosystem}:${dep.name}@${dep.version}`;

    const component: CycloneDXComponent = {
      type: "library",
      name: dep.name,
      version: dep.version,
      purl: dep.purl || `pkg:${dep.ecosystem}/${dep.name}@${dep.version}`,
      "bom-ref": bomRef,
      scope: dep.isDirect ? "required" : "optional",
      properties: [
        { name: "scato:ecosystem", value: dep.ecosystem },
        { name: "scato:isDirect", value: String(dep.isDirect) },
      ],
    };

    if (dep.scope) {
      component.properties!.push({ name: "scato:scope", value: dep.scope });
    }

    if (dep.license) {
      component.licenses = [
        {
          license: {
            id: dep.license,
          },
        },
      ];
    }

    components.push(component);

    // Build dependency graph
    if (dep.parent) {
      const parentRef = `${dep.ecosystem}:${dep.parent}`;
      // Find parent's actual bomRef
      const parentResult = results.find(
        (r) => r.dependency.name === dep.parent && r.dependency.ecosystem === dep.ecosystem
      );
      if (parentResult) {
        const parentBomRef = `${parentResult.dependency.ecosystem}:${parentResult.dependency.name}@${parentResult.dependency.version}`;
        if (!parentMap.has(parentBomRef)) {
          parentMap.set(parentBomRef, new Set());
        }
        parentMap.get(parentBomRef)!.add(bomRef);
      }
    }

    // Add vulnerabilities for this component
    for (const vuln of result.vulnerabilities) {
      const vulnEntry: CycloneDXVulnerability = {
        id: vuln.id,
        source: {
          name: vuln.source?.toUpperCase() || "OSV",
          url: getSourceUrl(vuln.id, vuln.source),
        },
        ratings: [
          {
            severity: vuln.severity.toLowerCase(),
            score: vuln.score,
            method: vuln.score ? "CVSSv31" : undefined,
            vector: vuln.cvssVector,
          },
        ],
        description: vuln.summary,
        affects: [{ ref: bomRef }],
      };

      // Add CWE references
      if (vuln.cwes?.length) {
        vulnEntry.cwes = vuln.cwes
          .map((cwe) => {
            const match = cwe.match(/CWE-(\d+)/);
            return match ? parseInt(match[1], 10) : null;
          })
          .filter((n): n is number => n !== null);
      }

      // Add EPSS and KEV as properties
      const props: Array<{ name: string; value: string }> = [];
      if (vuln.epssScore !== undefined) {
        props.push({ name: "scato:epss_score", value: String(vuln.epssScore) });
      }
      if (vuln.epssPercentile !== undefined) {
        props.push({ name: "scato:epss_percentile", value: String(vuln.epssPercentile) });
      }
      if (vuln.isKnownExploited) {
        props.push({ name: "scato:kev", value: "true" });
        if (vuln.kevDateAdded) {
          props.push({ name: "scato:kev_date_added", value: vuln.kevDateAdded });
        }
      }
      if (props.length > 0) {
        vulnEntry.properties = props;
      }

      vulnerabilities.push(vulnEntry);
    }
  }

  // Build dependency tree entries
  for (const [parentRef, childRefs] of parentMap) {
    dependencies.push({
      ref: parentRef,
      dependsOn: [...childRefs],
    });
  }

  // Add root-level dependencies (direct deps of the project)
  const rootRef = `scato:${projectName}`;
  const directDeps = results
    .filter((r) => r.dependency.isDirect)
    .map((r) => `${r.dependency.ecosystem}:${r.dependency.name}@${r.dependency.version}`);

  if (directDeps.length > 0) {
    dependencies.unshift({
      ref: rootRef,
      dependsOn: directDeps,
    });
  }

  const bom: CycloneDXBom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: {
        components: [
          {
            type: "application",
            name: "scato",
            version: "3.0.0",
          },
        ],
      },
      component: {
        type: "application",
        name: projectName,
      },
    },
    components,
    dependencies: dependencies.length > 0 ? dependencies : undefined,
    vulnerabilities: vulnerabilities.length > 0 ? vulnerabilities : undefined,
  };

  return bom;
}

export async function writeSBOM(bom: CycloneDXBom, outputPath: string): Promise<void> {
  await writeFile(outputPath, JSON.stringify(bom, null, 2));
}

function getSourceUrl(vulnId: string, source?: string): string {
  if (vulnId.startsWith("CVE-")) {
    return `https://nvd.nist.gov/vuln/detail/${vulnId}`;
  }
  if (vulnId.startsWith("GHSA-")) {
    return `https://github.com/advisories/${vulnId}`;
  }
  return `https://osv.dev/vulnerability/${vulnId}`;
}
