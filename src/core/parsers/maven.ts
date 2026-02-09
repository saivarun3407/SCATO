import { readFile } from "fs/promises";
import { join } from "path";
import { XMLParser } from "fast-xml-parser";
import type { Dependency, ParserResult } from "../../types.js";

export async function parseMaven(dir: string): Promise<ParserResult | null> {
  const pomPath = join(dir, "pom.xml");

  try {
    const content = await readFile(pomPath, "utf-8");
    return parsePom(content, pomPath);
  } catch {
    return null;
  }
}

function parsePom(content: string, file: string): ParserResult {
  const parser = new XMLParser({
    ignoreAttributes: false,
    isArray: (name) => name === "dependency",
  });

  const parsed = parser.parse(content);
  const deps: Dependency[] = [];

  const project = parsed.project;
  if (!project) return { ecosystem: "maven", file, dependencies: [] };

  // Collect properties for variable resolution
  const properties: Record<string, string> = {};
  if (project.properties) {
    for (const [key, value] of Object.entries(project.properties)) {
      if (typeof value === "string") {
        properties[key] = value;
      }
    }
  }
  // Add project version
  if (project.version) {
    properties["project.version"] = String(project.version);
  }

  // Parse direct dependencies
  const directDeps = project.dependencies?.dependency || [];
  for (const dep of Array.isArray(directDeps) ? directDeps : [directDeps]) {
    if (!dep || !dep.groupId || !dep.artifactId) continue;
    const version = resolveProperty(String(dep.version || "unknown"), properties);
    const groupId = String(dep.groupId);
    const artifactId = String(dep.artifactId);

    deps.push({
      name: `${groupId}:${artifactId}`,
      version,
      ecosystem: "maven",
      isDirect: true,
      purl: `pkg:maven/${groupId}/${artifactId}@${version}`,
    });
  }

  // Parse dependency management (often in parent POMs)
  const mgmtDeps =
    project.dependencyManagement?.dependencies?.dependency || [];
  for (const dep of Array.isArray(mgmtDeps) ? mgmtDeps : [mgmtDeps]) {
    if (!dep || !dep.groupId || !dep.artifactId) continue;
    const version = resolveProperty(String(dep.version || "unknown"), properties);
    const groupId = String(dep.groupId);
    const artifactId = String(dep.artifactId);
    const key = `${groupId}:${artifactId}`;

    // Don't duplicate if already in direct deps
    if (deps.some((d) => d.name === key)) continue;

    deps.push({
      name: key,
      version,
      ecosystem: "maven",
      isDirect: false,
      purl: `pkg:maven/${groupId}/${artifactId}@${version}`,
    });
  }

  return { ecosystem: "maven", file, dependencies: deps };
}

function resolveProperty(value: string, props: Record<string, string>): string {
  return value.replace(/\$\{([^}]+)\}/g, (_, key) => props[key] || `\${${key}}`);
}
