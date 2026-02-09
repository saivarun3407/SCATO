import { readFile } from "fs/promises";
import { join } from "path";
import { execFileSync } from "child_process";
import type { Dependency, ParserResult } from "../../types.js";

export async function parseCargo(dir: string): Promise<ParserResult | null> {
  const lockPath = join(dir, "Cargo.lock");
  const tomlPath = join(dir, "Cargo.toml");

  try {
    const lockContent = await readFile(lockPath, "utf-8");
    const tomlContent = await readFile(tomlPath, "utf-8").catch(() => "");

    // Try `cargo tree` for the richest dependency tree
    const cargoTreeDeps = tryCargoTree(dir);
    if (cargoTreeDeps && cargoTreeDeps.length > 0) {
      const directDeps = extractDirectFromCargoToml(tomlContent);
      // Merge cargo tree data with isDirect from Cargo.toml
      for (const dep of cargoTreeDeps) {
        dep.isDirect = directDeps.has(dep.name);
        if (dep.isDirect) dep.parent = undefined;
      }
      return { ecosystem: "cargo", file: lockPath, dependencies: cargoTreeDeps };
    }

    // Fall back to parsing Cargo.lock with dependency info
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

// ═══════════════════════════════════════════════════════════════
// cargo tree (richest source — full tree with parent info)
// ═══════════════════════════════════════════════════════════════

function tryCargoTree(dir: string): Dependency[] | null {
  try {
    // OWASP CWE-78: use execFileSync (no shell) with args as array
    const output = execFileSync("cargo", ["tree", "--prefix", "depth"], {
      cwd: dir,
      timeout: 30000,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });

    const deps: Dependency[] = [];
    const seen = new Set<string>();
    const parentStack: { name: string; depth: number }[] = [];

    for (const line of output.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      // Format with --prefix depth: "0name v1.0.0" or "1name v1.0.0"
      const match = trimmed.match(/^(\d+)(.+?)\s+v([\d.]+\S*)/);
      if (!match) continue;

      const depth = parseInt(match[1], 10);
      const name = match[2].trim();
      const version = match[3];

      if (seen.has(name)) continue;
      seen.add(name);

      // Determine parent
      while (parentStack.length > 0 && parentStack[parentStack.length - 1].depth >= depth) {
        parentStack.pop();
      }
      const parent = parentStack.length > 0 ? parentStack[parentStack.length - 1].name : undefined;
      parentStack.push({ name, depth });

      deps.push({
        name,
        version,
        ecosystem: "cargo",
        isDirect: depth <= 1,  // Will be corrected by caller using Cargo.toml
        parent: depth <= 1 ? undefined : parent,
        purl: `pkg:cargo/${name}@${version}`,
      });
    }

    return deps.length > 0 ? deps : null;
  } catch {
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════
// Cargo.lock parser with dependency graph
// ═══════════════════════════════════════════════════════════════

function parseCargoLock(lockContent: string, tomlContent: string, file: string): ParserResult {
  const deps: Dependency[] = [];
  const directDeps = extractDirectFromCargoToml(tomlContent);

  // Parse [[package]] blocks including their dependencies arrays
  const packages = lockContent.split("[[package]]");

  // First pass: collect all package info and their dependencies
  interface PkgInfo {
    name: string;
    version: string;
    deps: string[]; // "name version" pairs from dependencies array
  }
  const allPkgs: PkgInfo[] = [];

  for (const block of packages) {
    const nameMatch = block.match(/name\s*=\s*"([^"]+)"/);
    const versionMatch = block.match(/version\s*=\s*"([^"]+)"/);

    if (!nameMatch || !versionMatch) continue;

    const name = nameMatch[1];
    const version = versionMatch[1];

    // Extract dependencies array from this package block
    // Format: dependencies = [\n "dep1 version",\n "dep2 version",\n]
    const pkgDeps: string[] = [];
    const depsMatch = block.match(/dependencies\s*=\s*\[([\s\S]*?)\]/);
    if (depsMatch) {
      const depsBlock = depsMatch[1];
      // Each line: "package-name version" or "package-name"
      const depRegex = /"([^"]+)"/g;
      let depMatch: RegExpExecArray | null;
      while ((depMatch = depRegex.exec(depsBlock)) !== null) {
        // Extract just the package name (first word)
        const depName = depMatch[1].split(/\s+/)[0];
        pkgDeps.push(depName);
      }
    }

    allPkgs.push({ name, version, deps: pkgDeps });
  }

  // Build reverse parent map: child name -> first parent name
  const childToParent = new Map<string, string>();
  for (const pkg of allPkgs) {
    for (const depName of pkg.deps) {
      if (!childToParent.has(depName)) {
        childToParent.set(depName, pkg.name);
      }
    }
  }

  // Get root package name (from Cargo.toml) to exclude it
  const rootPkgMatch = tomlContent.match(/^\[package\][\s\S]*?name\s*=\s*"([^"]+)"/m);
  const rootPkgName = rootPkgMatch ? rootPkgMatch[1] : "";

  // Build dependency list
  for (const pkg of allPkgs) {
    // Skip the root package itself
    if (pkg.name === rootPkgName) continue;

    const isDirect = directDeps.has(pkg.name);
    const parent = isDirect ? undefined : (childToParent.get(pkg.name) || undefined);
    // Don't set root package as parent (it's implicit)
    const cleanParent = parent === rootPkgName ? undefined : parent;

    deps.push({
      name: pkg.name,
      version: pkg.version,
      ecosystem: "cargo",
      isDirect,
      parent: cleanParent,
      purl: `pkg:cargo/${pkg.name}@${pkg.version}`,
    });
  }

  return { ecosystem: "cargo", file, dependencies: deps };
}

// ═══════════════════════════════════════════════════════════════
// Cargo.toml parser (direct deps only, fallback)
// ═══════════════════════════════════════════════════════════════

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
    if (trimmed === "[dev-dependencies]" || trimmed === "[dev_dependencies]") {
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
        scope: inDevDeps ? "dev" : "runtime",
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
        scope: inDevDeps ? "dev" : "runtime",
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
    if (trimmed === "[dependencies]" || trimmed === "[dev-dependencies]" || trimmed === "[dev_dependencies]") {
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
