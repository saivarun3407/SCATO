import { readFile } from "fs/promises";
import { join } from "path";
import type { Dependency, ParserResult } from "../../types.js";

export async function parseNpm(dir: string): Promise<ParserResult | null> {
  const lockPath = join(dir, "package-lock.json");
  const bunLockPath = join(dir, "bun.lock");
  const yarnLockPath = join(dir, "yarn.lock");
  const pkgPath = join(dir, "package.json");

  // Read package.json for direct dep names (used by yarn.lock parser)
  let pkgJsonContent: string | null = null;
  try { pkgJsonContent = await readFile(pkgPath, "utf-8"); } catch {}

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

  // 3. Try yarn.lock (Yarn — has all resolved packages)
  try {
    const yarnContent = await readFile(yarnLockPath, "utf-8");
    return parseYarnLock(yarnContent, yarnLockPath, pkgJsonContent);
  } catch { /* not found, try next */ }

  // 4. Fall back to package.json (direct deps only, no tree)
  try {
    const content = pkgJsonContent || await readFile(pkgPath, "utf-8");
    return parsePackageJson(content, pkgPath);
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

/**
 * Parse yarn.lock (Yarn v1 classic and Yarn v2+ berry).
 * yarn.lock lists every resolved package with version and dependencies.
 * Cross-ref package.json to determine direct vs transitive.
 */
function parseYarnLock(content: string, file: string, pkgJsonContent: string | null): ParserResult {
  const deps: Dependency[] = [];
  const directNames = new Set<string>();

  // Get direct dep names from package.json
  if (pkgJsonContent) {
    try {
      const pkg = JSON.parse(pkgJsonContent);
      for (const name of Object.keys(pkg.dependencies || {})) directNames.add(name);
      for (const name of Object.keys(pkg.devDependencies || {})) directNames.add(name);
    } catch {}
  }

  const seen = new Set<string>();
  const blocks = content.split(/\n(?=[^\s#])/);
  const pkgDepsMap = new Map<string, string[]>();

  for (const block of blocks) {
    const lines = block.split("\n");
    const header = lines[0];
    if (!header || header.startsWith("#") || header.startsWith("__metadata")) continue;

    // Extract package name from header
    const headerClean = header.replace(/["']/g, "").replace(/:$/, "");
    const firstSpec = headerClean.split(",")[0].trim();
    const atIdx = firstSpec.lastIndexOf("@");
    let pkgName: string | null = null;
    if (atIdx > 0) {
      pkgName = firstSpec.substring(0, atIdx);
    } else if (firstSpec.match(/^[a-zA-Z@]/)) {
      pkgName = firstSpec;
    }
    if (!pkgName) continue;

    let resolvedVersion = "";
    const childDeps: string[] = [];
    let inDepsBlock = false;

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (!resolvedVersion) {
        const vMatch = trimmed.match(/^version\s+["']?([^"'\s]+)["']?/) ||
                       trimmed.match(/^version:\s+["']?([^"'\s]+)["']?/);
        if (vMatch) { resolvedVersion = vMatch[1]; continue; }
      }

      if (trimmed === "dependencies:" || trimmed.startsWith("dependencies:")) {
        inDepsBlock = true; continue;
      }
      if (inDepsBlock && !line.startsWith("    ") && trimmed !== "") {
        inDepsBlock = false;
      }
      if (inDepsBlock) {
        const depMatch = trimmed.match(/^["']?([^"'\s]+)["']?\s/);
        if (depMatch) childDeps.push(depMatch[1]);
      }
    }

    if (!resolvedVersion) continue;
    const key = `${pkgName}@${resolvedVersion}`;
    if (seen.has(key)) continue;
    seen.add(key);
    pkgDepsMap.set(pkgName, childDeps);

    deps.push({
      name: pkgName,
      version: resolvedVersion,
      ecosystem: "npm",
      isDirect: directNames.has(pkgName),
      purl: `pkg:npm/${encodeURIComponent(pkgName)}@${resolvedVersion}`,
    });
  }

  // Build parent relationships for transitive deps
  for (const dep of deps) {
    if (!dep.isDirect) {
      for (const [parentName, children] of pkgDepsMap) {
        if (children.includes(dep.name)) { dep.parent = parentName; break; }
      }
    }
  }

  return { ecosystem: "npm", file, dependencies: deps };
}
