import { readFile } from "fs/promises";
import { join } from "path";
import type { Dependency, ParserResult } from "../../types.js";

export async function parsePip(dir: string): Promise<ParserResult | null> {
  // Try Pipfile.lock first (has transitive deps with hashes)
  const pipfileLockPath = join(dir, "Pipfile.lock");
  const requirementsPath = join(dir, "requirements.txt");

  try {
    const content = await readFile(pipfileLockPath, "utf-8");
    return parsePipfileLock(content, pipfileLockPath);
  } catch {
    try {
      const content = await readFile(requirementsPath, "utf-8");
      return parseRequirements(content, requirementsPath);
    } catch {
      return null;
    }
  }
}

function parsePipfileLock(content: string, file: string): ParserResult {
  const lock = JSON.parse(content);
  const deps: Dependency[] = [];

  for (const section of ["default", "develop"]) {
    const packages = lock[section];
    if (!packages) continue;

    for (const [name, info] of Object.entries(packages)) {
      const pkg = info as any;
      const version = (pkg.version || "").replace(/^==/, "");
      if (!version) continue;

      deps.push({
        name: name.toLowerCase(),
        version,
        ecosystem: "pip",
        isDirect: section === "default",
        purl: `pkg:pypi/${name.toLowerCase()}@${version}`,
      });
    }
  }

  return { ecosystem: "pip", file, dependencies: deps };
}

function parseRequirements(content: string, file: string): ParserResult {
  const deps: Dependency[] = [];

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    // Skip comments, blank lines, flags, URLs
    if (!line || line.startsWith("#") || line.startsWith("-") || line.startsWith("http")) continue;

    // Handle: package==1.2.3, package>=1.2.3, package~=1.2.3
    const match = line.match(/^([a-zA-Z0-9._-]+)\s*[=~><!\[]+([\d][^\s;#,]*)?/);
    if (match) {
      const name = match[1].toLowerCase();
      const version = match[2] || "unknown";
      deps.push({
        name,
        version,
        ecosystem: "pip",
        isDirect: true,
        purl: `pkg:pypi/${name}@${version}`,
      });
    } else if (line.match(/^[a-zA-Z0-9._-]+$/)) {
      // Just a package name, no version
      deps.push({
        name: line.toLowerCase(),
        version: "unknown",
        ecosystem: "pip",
        isDirect: true,
        purl: `pkg:pypi/${line.toLowerCase()}`,
      });
    }
  }

  return { ecosystem: "pip", file, dependencies: deps };
}
