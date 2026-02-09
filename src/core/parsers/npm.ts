import { readFile } from "fs/promises";
import { join } from "path";
import type { Dependency, ParserResult } from "../../types.js";

export async function parseNpm(dir: string): Promise<ParserResult | null> {
  const lockPath = join(dir, "package-lock.json");
  const bunLockPath = join(dir, "bun.lock");
  const pkgPath = join(dir, "package.json");

  // 1. Try package-lock.json (npm — has transitive deps with parent info)
  try {
    const lockContent = await readFile(lockPath, "utf-8");
    return parseLockfile(lockContent, lockPath);
  } catch { /* not found, try next */ }

  // 2. Try bun.lock (Bun — has transitive deps with dependency graph)
  try {
    const bunContent = await readFile(bunLockPath, "utf-8");
    return parseBunLock(bunContent, bunLockPath);
  } catch { /* not found, try next */ }

  // 3. Fall back to package.json (direct deps only, no tree)
  try {
    const pkgContent = await readFile(pkgPath, "utf-8");
    return parsePackageJson(pkgContent, pkgPath);
  } catch {
    return null;
  }
}

/**
 * Parse bun.lock (Bun's lockfile).
 * Format: { workspaces: { "": { dependencies, devDependencies } }, packages: { name: [name@ver, "", {dependencies}, hash] } }
 * bun.lock uses JSONC (trailing commas allowed), so we strip them before parsing.
 */
function parseBunLock(content: string, file: string): ParserResult {
  // bun.lock has trailing commas (not valid JSON) — strip them
  const cleaned = content.replace(/,(\s*[}\]])/g, "$1");
  const lock = JSON.parse(cleaned);
  const deps: Dependency[] = [];

  // Collect direct dependency names from workspace root
  const directDeps = new Set<string>();
  const ws = lock.workspaces || {};
  const root = ws[""] || {};
  if (root.dependencies) {
    Object.keys(root.dependencies).forEach((n) => directDeps.add(n));
  }
  if (root.devDependencies) {
    Object.keys(root.devDependencies).forEach((n) => directDeps.add(n));
  }

  // packages: { "name": ["name@version", registry, {dependencies?, peerDependencies?}, hash] }
  const pkgs = lock.packages || {};

  // Build a map: packageName -> its dependency names (for parent resolution)
  const pkgDepsMap = new Map<string, string[]>();
  const pkgVersionMap = new Map<string, string>(); // name -> version

  for (const [pkgName, entry] of Object.entries(pkgs)) {
    if (!Array.isArray(entry) || entry.length < 1) continue;
    const nameAtVer = (entry as any[])[0] as string;
    const meta = (entry as any[])[2] as Record<string, any> | undefined;

    // Extract version from "name@version"
    const atIdx = nameAtVer.lastIndexOf("@");
    const version = atIdx > 0 ? nameAtVer.slice(atIdx + 1) : "";

    // Resolve the actual package name (bun.lock can have scoped keys like "log-symbols/is-unicode-supported")
    const slashIdx = pkgName.indexOf("/");
    const isScoped = pkgName.startsWith("@");
    let resolvedName = pkgName;
    // Keys like "bun-types/@types/node" mean @types/node brought in by bun-types
    if (!isScoped && slashIdx !== -1) {
      resolvedName = pkgName.slice(slashIdx + 1);
    }

    pkgVersionMap.set(resolvedName, version);

    // Collect dependency names
    const depNames: string[] = [];
    if (meta) {
      if (meta.dependencies) depNames.push(...Object.keys(meta.dependencies));
      if (meta.peerDependencies) depNames.push(...Object.keys(meta.peerDependencies));
    }
    pkgDepsMap.set(resolvedName, depNames);
  }

  // Build reverse map: childName -> parentName (who depends on this package)
  const childToParent = new Map<string, string>();
  for (const [parentName, depNames] of pkgDepsMap) {
    for (const childName of depNames) {
      if (!childToParent.has(childName)) {
        childToParent.set(childName, parentName);
      }
    }
  }

  // Build Dependency[] from packages
  for (const [pkgName, entry] of Object.entries(pkgs)) {
    if (!Array.isArray(entry) || entry.length < 1) continue;
    const nameAtVer = (entry as any[])[0] as string;
    const atIdx = nameAtVer.lastIndexOf("@");
    const version = atIdx > 0 ? nameAtVer.slice(atIdx + 1) : "";

    const isScoped = pkgName.startsWith("@");
    const slashIdx = pkgName.indexOf("/");
    let resolvedName = pkgName;
    let parentFromKey: string | undefined;

    // Keys like "bun-types/@types/node" → name is "@types/node", parent is "bun-types"
    if (!isScoped && slashIdx !== -1) {
      parentFromKey = pkgName.slice(0, slashIdx);
      resolvedName = pkgName.slice(slashIdx + 1);
    }

    const isDirect = directDeps.has(resolvedName);

    // Determine parent: from key path, or from reverse dependency map (skip if direct)
    let parent: string | undefined = parentFromKey;
    if (!parent && !isDirect) {
      parent = childToParent.get(resolvedName);
      // Don't set parent to self
      if (parent === resolvedName) parent = undefined;
    }

    deps.push({
      name: resolvedName,
      version,
      ecosystem: "npm",
      isDirect,
      parent,
      purl: `pkg:npm/${encodeURIComponent(resolvedName)}@${version}`,
    });
  }

  return { ecosystem: "npm", file, dependencies: deps };
}

function parseLockfile(content: string, file: string): ParserResult {
  const lock = JSON.parse(content);
  const deps: Dependency[] = [];
  const directDeps = new Set<string>();

  // Get direct deps from the root
  if (lock.dependencies) {
    Object.keys(lock.dependencies).forEach((name) => directDeps.add(name));
  }

  // lockfileVersion 2/3 uses "packages" (path = node_modules/foo or node_modules/bar/node_modules/foo)
  if (lock.packages) {
    for (const [path, info] of Object.entries(lock.packages)) {
      if (path === "") continue; // skip root
      const pkg = info as any;
      const segments = path.replace(/^node_modules\//, "").split("/node_modules/");
      const name = segments[segments.length - 1];
      const parent = segments.length > 1 ? segments[segments.length - 2] : undefined;
      if (!name || !pkg.version) continue;

      deps.push({
        name,
        version: pkg.version,
        ecosystem: "npm",
        isDirect: directDeps.has(name),
        parent,
        license: pkg.license,
        purl: `pkg:npm/${encodeURIComponent(name)}@${pkg.version}`,
      });
    }
  }
  // lockfileVersion 1 uses top-level "dependencies"
  else if (lock.dependencies) {
    parseDepsRecursive(lock.dependencies, deps, directDeps);
  }

  return { ecosystem: "npm", file, dependencies: deps };
}

function parseDepsRecursive(
  depsObj: Record<string, any>,
  result: Dependency[],
  directDeps: Set<string>,
  parent?: string
) {
  for (const [name, info] of Object.entries(depsObj)) {
    const pkg = info as any;
    if (!pkg.version) continue;

    result.push({
      name,
      version: pkg.version,
      ecosystem: "npm",
      isDirect: directDeps.has(name),
      parent,
      purl: `pkg:npm/${encodeURIComponent(name)}@${pkg.version}`,
    });

    if (pkg.dependencies) {
      parseDepsRecursive(pkg.dependencies, result, directDeps, name);
    }
  }
}

function parsePackageJson(content: string, file: string): ParserResult {
  const pkg = JSON.parse(content);
  const deps: Dependency[] = [];

  const allDeps: Record<string, string> = {
    ...(pkg.dependencies || {}),
    ...(pkg.devDependencies || {}),
  };

  for (const [name, versionRange] of Object.entries(allDeps)) {
    // Strip version prefixes (^, ~, >=, etc.)
    const version = versionRange.replace(/^[\^~>=<]*/, "").split(" ")[0];
    deps.push({
      name,
      version,
      ecosystem: "npm",
      isDirect: true,
      purl: `pkg:npm/${encodeURIComponent(name)}@${version}`,
    });
  }

  return { ecosystem: "npm", file, dependencies: deps };
}
