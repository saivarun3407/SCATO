import { readFile } from "fs/promises";
import { join } from "path";
import { execSync } from "child_process";
import type { Dependency, ParserResult } from "../../types.js";

export async function parseGo(dir: string): Promise<ParserResult | null> {
  const goSumPath = join(dir, "go.sum");
  const goModPath = join(dir, "go.mod");

  try {
    const sumContent = await readFile(goSumPath, "utf-8");
    const modContent = await readFile(goModPath, "utf-8").catch(() => "");

    // Try `go mod graph` for full dependency tree with parent info
    const graphEdges = tryGoModGraph(dir);

    return parseGoSum(sumContent, modContent, goSumPath, graphEdges);
  } catch {
    try {
      const content = await readFile(goModPath, "utf-8");
      const graphEdges = tryGoModGraph(dir);
      return parseGoMod(content, goModPath, graphEdges);
    } catch {
      return null;
    }
  }
}

/** Run `go mod graph` and return edges as [parent, child] pairs */
function tryGoModGraph(dir: string): Array<[string, string]> {
  try {
    const output = execSync("go mod graph 2>/dev/null", {
      cwd: dir,
      timeout: 30000,
      encoding: "utf-8",
    });

    const edges: Array<[string, string]> = [];
    for (const line of output.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      // Format: parent@version child@version
      const parts = trimmed.split(/\s+/);
      if (parts.length === 2) {
        // Extract module names (strip version)
        const parentModule = parts[0].replace(/@[^@]+$/, "");
        const childModule = parts[1].replace(/@[^@]+$/, "");
        edges.push([parentModule, childModule]);
      }
    }
    return edges;
  } catch {
    return [];
  }
}

/** Build a parent map from graph edges: child -> first parent */
function buildParentMap(edges: Array<[string, string]>, rootModule: string): Map<string, string> {
  const parentMap = new Map<string, string>();
  for (const [parent, child] of edges) {
    if (!parentMap.has(child) && child !== rootModule) {
      // Don't set root module as its own parent
      parentMap.set(child, parent === rootModule ? "" : parent);
    }
  }
  return parentMap;
}

/** Extract the module name from go.mod */
function extractModuleName(content: string): string {
  const match = content.match(/^module\s+(\S+)/m);
  return match ? match[1] : "";
}

function parseGoSum(
  sumContent: string,
  modContent: string,
  file: string,
  graphEdges: Array<[string, string]>
): ParserResult {
  const deps: Dependency[] = [];
  const seen = new Set<string>();
  const directDeps = extractDirectFromGoMod(modContent);
  const rootModule = extractModuleName(modContent);
  const parentMap = buildParentMap(graphEdges, rootModule);

  for (const line of sumContent.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Format: module version hash
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

    const isDirect = directDeps.has(modulePath);
    const parent = isDirect ? undefined : (parentMap.get(modulePath) || undefined);

    deps.push({
      name: modulePath,
      version,
      ecosystem: "go",
      isDirect,
      parent,
      purl: `pkg:golang/${modulePath}@${version}`,
    });
  }

  return { ecosystem: "go", file, dependencies: deps };
}

function parseGoMod(
  content: string,
  file: string,
  graphEdges: Array<[string, string]>
): ParserResult {
  const deps: Dependency[] = [];
  const directDeps = extractDirectFromGoMod(content);
  const rootModule = extractModuleName(content);
  const parentMap = buildParentMap(graphEdges, rootModule);

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
      const name = singleMatch[1];
      const isDirect = directDeps.has(name);
      const isIndirect = trimmed.includes("// indirect");
      deps.push({
        name,
        version: singleMatch[2].replace(/\+incompatible$/, ""),
        ecosystem: "go",
        isDirect: isDirect && !isIndirect,
        parent: isIndirect ? (parentMap.get(name) || undefined) : undefined,
        purl: `pkg:golang/${name}@${singleMatch[2]}`,
      });
      continue;
    }

    // Multi-line require block
    if (inRequire) {
      const match = trimmed.match(/^(\S+)\s+(\S+)/);
      if (match && !match[0].startsWith("//")) {
        const name = match[1];
        const isIndirect = trimmed.includes("// indirect");
        const isDirect = directDeps.has(name) && !isIndirect;
        deps.push({
          name,
          version: match[2].replace(/\+incompatible$/, ""),
          ecosystem: "go",
          isDirect,
          parent: !isDirect ? (parentMap.get(name) || undefined) : undefined,
          purl: `pkg:golang/${name}@${match[2]}`,
        });
      }
    }
  }

  return { ecosystem: "go", file, dependencies: deps };
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
