import { readFile } from "fs/promises";
import { join } from "path";
import type { Dependency, ParserResult } from "../../types.js";

export async function parseCargo(dir: string): Promise<ParserResult | null> {
  const lockPath = join(dir, "Cargo.lock");
  const tomlPath = join(dir, "Cargo.toml");

  try {
    const lockContent = await readFile(lockPath, "utf-8");
    const tomlContent = await readFile(tomlPath, "utf-8").catch(() => "");
    return parseCargoLock(lockContent, tomlContent, lockPath);
  } catch {
    try {
      const content = await readFile(tomlPath, "utf-8");
      return parseCargoToml(content, tomlPath);
    } catch {
      return null;
    }
  }
}

function parseCargoLock(lockContent: string, tomlContent: string, file: string): ParserResult {
  const deps: Dependency[] = [];
  const directDeps = extractDirectFromCargoToml(tomlContent);

  // Cargo.lock format: [[package]] blocks
  const packages = lockContent.split("[[package]]");

  for (const block of packages) {
    const nameMatch = block.match(/name\s*=\s*"([^"]+)"/);
    const versionMatch = block.match(/version\s*=\s*"([^"]+)"/);

    if (!nameMatch || !versionMatch) continue;

    const name = nameMatch[1];
    const version = versionMatch[1];

    deps.push({
      name,
      version,
      ecosystem: "cargo",
      isDirect: directDeps.has(name),
      purl: `pkg:cargo/${name}@${version}`,
    });
  }

  return { ecosystem: "cargo", file, dependencies: deps };
}

function parseCargoToml(content: string, file: string): ParserResult {
  const deps: Dependency[] = [];
  let inDeps = false;
  let inDevDeps = false;

  for (const line of content.split("\n")) {
    const trimmed = line.trim();

    if (trimmed === "[dependencies]") {
      inDeps = true;
      inDevDeps = false;
      continue;
    }
    if (trimmed === "[dev-dependencies]") {
      inDeps = false;
      inDevDeps = true;
      continue;
    }
    if (trimmed.startsWith("[")) {
      inDeps = false;
      inDevDeps = false;
      continue;
    }

    if (!inDeps && !inDevDeps) continue;

    // name = "version" or name = { version = "1.0" }
    const simpleMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
    if (simpleMatch) {
      deps.push({
        name: simpleMatch[1],
        version: simpleMatch[2],
        ecosystem: "cargo",
        isDirect: true,
        purl: `pkg:cargo/${simpleMatch[1]}@${simpleMatch[2]}`,
      });
      continue;
    }

    const tableMatch = trimmed.match(
      /^([a-zA-Z0-9_-]+)\s*=\s*\{.*version\s*=\s*"([^"]+)"/
    );
    if (tableMatch) {
      deps.push({
        name: tableMatch[1],
        version: tableMatch[2],
        ecosystem: "cargo",
        isDirect: true,
        purl: `pkg:cargo/${tableMatch[1]}@${tableMatch[2]}`,
      });
    }
  }

  return { ecosystem: "cargo", file, dependencies: deps };
}

function extractDirectFromCargoToml(content: string): Set<string> {
  const direct = new Set<string>();
  if (!content) return direct;

  let inDeps = false;
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (trimmed === "[dependencies]" || trimmed === "[dev-dependencies]") {
      inDeps = true;
      continue;
    }
    if (trimmed.startsWith("[")) {
      inDeps = false;
      continue;
    }
    if (inDeps) {
      const match = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=/);
      if (match) direct.add(match[1]);
    }
  }
  return direct;
}
