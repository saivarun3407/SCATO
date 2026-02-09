import { readFile } from "fs/promises";
import { join } from "path";
import type { Dependency, ParserResult } from "../../types.js";

export async function parseGo(dir: string): Promise<ParserResult | null> {
  const goSumPath = join(dir, "go.sum");
  const goModPath = join(dir, "go.mod");

  try {
    const sumContent = await readFile(goSumPath, "utf-8");
    const modContent = await readFile(goModPath, "utf-8").catch(() => "");
    return parseGoSum(sumContent, modContent, goSumPath);
  } catch {
    try {
      const content = await readFile(goModPath, "utf-8");
      return parseGoMod(content, goModPath);
    } catch {
      return null;
    }
  }
}

function parseGoSum(sumContent: string, modContent: string, file: string): ParserResult {
  const deps: Dependency[] = [];
  const seen = new Set<string>();
  const directDeps = extractDirectFromGoMod(modContent);

  for (const line of sumContent.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Format: module version hash
    // e.g., github.com/gin-gonic/gin v1.9.1 h1:abc...
    const parts = trimmed.split(/\s+/);
    if (parts.length < 3) continue;

    const modulePath = parts[0];
    let version = parts[1];

    // Skip /go.mod entries (keep only the source entries)
    if (version.endsWith("/go.mod")) continue;

    // Strip +incompatible suffix
    version = version.replace(/\+incompatible$/, "");

    const key = `${modulePath}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    deps.push({
      name: modulePath,
      version,
      ecosystem: "go",
      isDirect: directDeps.has(modulePath),
      purl: `pkg:golang/${modulePath}@${version}`,
    });
  }

  return { ecosystem: "go", file, dependencies: deps };
}

function parseGoMod(content: string, file: string): ParserResult {
  const deps: Dependency[] = [];
  let inRequire = false;

  for (const line of content.split("\n")) {
    const trimmed = line.trim();

    if (trimmed.startsWith("require (")) {
      inRequire = true;
      continue;
    }
    if (trimmed === ")") {
      inRequire = false;
      continue;
    }

    // Single-line require
    const singleMatch = trimmed.match(/^require\s+(\S+)\s+(\S+)/);
    if (singleMatch) {
      deps.push(makeDep(singleMatch[1], singleMatch[2]));
      continue;
    }

    // Multi-line require block
    if (inRequire) {
      const match = trimmed.match(/^(\S+)\s+(\S+)/);
      if (match && !match[0].startsWith("//")) {
        deps.push(makeDep(match[1], match[2]));
      }
    }
  }

  return { ecosystem: "go", file, dependencies: deps };
}

function makeDep(name: string, version: string): Dependency {
  version = version.replace(/\+incompatible$/, "");
  return {
    name,
    version,
    ecosystem: "go",
    isDirect: true,
    purl: `pkg:golang/${name}@${version}`,
  };
}

function extractDirectFromGoMod(content: string): Set<string> {
  const direct = new Set<string>();
  if (!content) return direct;

  let inRequire = false;
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.startsWith("require (")) {
      inRequire = true;
      continue;
    }
    if (trimmed === ")") {
      inRequire = false;
      continue;
    }
    if (trimmed.includes("// indirect")) continue;

    const match = trimmed.match(/^(?:require\s+)?(\S+)\s+/);
    if (match && (inRequire || trimmed.startsWith("require "))) {
      direct.add(match[1]);
    }
  }
  return direct;
}
