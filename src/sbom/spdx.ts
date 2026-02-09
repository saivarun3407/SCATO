// ─── SPDX SBOM Generator ───
// Generates Software Bill of Materials in SPDX 2.3 format
// https://spdx.github.io/spdx-spec/v2.3/

import { writeFile } from "fs/promises";
import { randomUUID } from "crypto";
import type { ScanResult, Dependency, Ecosystem } from "../types.js";

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

interface SPDXDocument {
    spdxVersion: "SPDX-2.3";
    dataLicense: "CC0-1.0";
    SPDXID: string;
    name: string;
    documentNamespace: string;
    creationInfo: {
        created: string;
        creators: string[];
        licenseListVersion?: string;
    };
    packages: SPDXPackage[];
    relationships: SPDXRelationship[];
    externalDocumentRefs?: SPDXExternalDocumentRef[];
}

interface SPDXPackage {
    SPDXID: string;
    name: string;
    versionInfo: string;
    downloadLocation: string;
    filesAnalyzed: false;
    licenseConcluded: string;
    licenseDeclared: string;
    copyrightText: string;
    externalRefs: SPDXExternalRef[];
    supplier?: string;
    checksums?: Array<{
        algorithm: string;
        checksumValue: string;
    }>;
    primaryPackagePurpose?: string;
}

interface SPDXRelationship {
    spdxElementId: string;
    relatedSpdxElement: string;
    relationshipType: string;
}

interface SPDXExternalRef {
    referenceCategory: string;
    referenceType: string;
    referenceLocator: string;
}

interface SPDXExternalDocumentRef {
    externalDocumentId: string;
    spdxDocument: string;
    checksum: {
        algorithm: string;
        checksumValue: string;
    };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Ecosystem to PURL type mapping
// ═══════════════════════════════════════════════════════════════════════════════

const ECOSYSTEM_TO_PURL: Record<Ecosystem, string> = {
    npm: "npm",
    pip: "pypi",
    go: "golang",
    maven: "maven",
    cargo: "cargo",
    nuget: "nuget",
    gem: "gem",
    composer: "composer",
};

const ECOSYSTEM_TO_DOWNLOAD: Record<Ecosystem, (name: string, version: string) => string> = {
    npm: (n, v) => `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz`,
    pip: (n, v) => `https://pypi.org/packages/${n}/${v}/`,
    go: (n, v) => `https://proxy.golang.org/${n}/@v/${v}.zip`,
    maven: (n, v) => {
        const [group, artifact] = n.split(":");
        return `https://repo1.maven.org/maven2/${group.replace(/\./g, "/")}/${artifact}/${v}/`;
    },
    cargo: (n, v) => `https://crates.io/api/v1/crates/${n}/${v}/download`,
    nuget: (n, v) => `https://www.nuget.org/api/v2/package/${n}/${v}`,
    gem: (n, v) => `https://rubygems.org/gems/${n}-${v}.gem`,
    composer: (n, v) => `https://packagist.org/packages/${n}#${v}`,
};

// ═══════════════════════════════════════════════════════════════════════════════
// Generator Functions
// ═══════════════════════════════════════════════════════════════════════════════

export function generateSPDX(
    projectName: string,
    results: ScanResult[]
): SPDXDocument {
    const documentId = randomUUID();
    const timestamp = new Date().toISOString();

    const packages: SPDXPackage[] = [];
    const relationships: SPDXRelationship[] = [];

    // Root package (the project being analyzed)
    const rootSpdxId = "SPDXRef-DOCUMENT";
    packages.push({
        SPDXID: "SPDXRef-RootPackage",
        name: projectName,
        versionInfo: "0.0.0",
        downloadLocation: "NOASSERTION",
        filesAnalyzed: false,
        licenseConcluded: "NOASSERTION",
        licenseDeclared: "NOASSERTION",
        copyrightText: "NOASSERTION",
        externalRefs: [],
        primaryPackagePurpose: "APPLICATION",
    });

    relationships.push({
        spdxElementId: rootSpdxId,
        relatedSpdxElement: "SPDXRef-RootPackage",
        relationshipType: "DESCRIBES",
    });

    // Process each dependency
    for (const result of results) {
        const dep = result.dependency;
        const spdxId = `SPDXRef-Package-${sanitizeSpdxId(dep.ecosystem)}-${sanitizeSpdxId(dep.name)}-${sanitizeSpdxId(dep.version)}`;
        const purl = dep.purl || generatePurl(dep);

        packages.push({
            SPDXID: spdxId,
            name: dep.name,
            versionInfo: dep.version,
            downloadLocation: getDownloadLocation(dep),
            filesAnalyzed: false,
            licenseConcluded: dep.license || "NOASSERTION",
            licenseDeclared: dep.license || "NOASSERTION",
            copyrightText: "NOASSERTION",
            externalRefs: [
                {
                    referenceCategory: "PACKAGE-MANAGER",
                    referenceType: "purl",
                    referenceLocator: purl,
                },
                // Add security references for vulnerabilities
                ...result.vulnerabilities.map((vuln) => ({
                    referenceCategory: "SECURITY",
                    referenceType: vuln.id.startsWith("CVE-") ? "cve" : "advisory",
                    referenceLocator: vuln.id,
                })),
            ],
            supplier: getSupplier(dep),
        });

        // Add relationship to root package
        const relationshipType = dep.isDirect ? "DEPENDS_ON" : "DEPENDENCY_OF";
        relationships.push({
            spdxElementId: "SPDXRef-RootPackage",
            relatedSpdxElement: spdxId,
            relationshipType,
        });

        // Add parent relationship if transitive
        if (!dep.isDirect && dep.parent) {
            const parentId = findParentSpdxId(dep.parent, dep.ecosystem, packages);
            if (parentId) {
                relationships.push({
                    spdxElementId: spdxId,
                    relatedSpdxElement: parentId,
                    relationshipType: "DEPENDENCY_OF",
                });
            }
        }
    }

    return {
        spdxVersion: "SPDX-2.3",
        dataLicense: "CC0-1.0",
        SPDXID: rootSpdxId,
        name: `${projectName} SBOM`,
        documentNamespace: `https://scato.dev/spdx/${projectName}/${documentId}`,
        creationInfo: {
            created: timestamp,
            creators: [
                "Tool: SCATO-3.0.0",
                "Organization: SCATO",
            ],
            licenseListVersion: "3.21",
        },
        packages,
        relationships,
    };
}

export async function writeSPDX(
    document: SPDXDocument,
    outputPath: string
): Promise<void> {
    const json = JSON.stringify(document, null, 2);
    await writeFile(outputPath, json, "utf-8");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════════════════════

function sanitizeSpdxId(input: string): string {
    // SPDX IDs can only contain letters, numbers, periods, and hyphens
    return input.replace(/[^a-zA-Z0-9.-]/g, "-").replace(/-+/g, "-");
}

function generatePurl(dep: Dependency): string {
    const type = ECOSYSTEM_TO_PURL[dep.ecosystem] || dep.ecosystem;
    const encodedName = encodeURIComponent(dep.name).replace(/%2F/g, "/");
    return `pkg:${type}/${encodedName}@${dep.version}`;
}

function getDownloadLocation(dep: Dependency): string {
    const generator = ECOSYSTEM_TO_DOWNLOAD[dep.ecosystem];
    if (generator) {
        return generator(dep.name, dep.version);
    }
    return "NOASSERTION";
}

function getSupplier(dep: Dependency): string {
    // Extract organization from package name where applicable
    switch (dep.ecosystem) {
        case "npm":
            if (dep.name.startsWith("@")) {
                const org = dep.name.split("/")[0].substring(1);
                return `Organization: ${org}`;
            }
            break;
        case "maven":
            if (dep.name.includes(":")) {
                const group = dep.name.split(":")[0];
                return `Organization: ${group}`;
            }
            break;
    }
    return "NOASSERTION";
}

function findParentSpdxId(
    parentName: string,
    ecosystem: Ecosystem,
    packages: SPDXPackage[]
): string | undefined {
    const prefix = `SPDXRef-Package-${sanitizeSpdxId(ecosystem)}-${sanitizeSpdxId(parentName)}`;
    return packages.find((p) => p.SPDXID.startsWith(prefix))?.SPDXID;
}
