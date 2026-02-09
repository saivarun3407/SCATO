import { readFile, readdir, access } from "fs/promises";
import { join, resolve } from "path";
import { execSync } from "child_process";
import type { Dependency, ParserResult } from "../../types.js";

export async function parsePip(dir: string): Promise<ParserResult | null> {
  // Try lockfiles in order of richness:
  // 1. poetry.lock  (has full dependency graph)
  // 2. Pipfile.lock (has all resolved packages, cross-ref Pipfile for direct)
  // 3. pip metadata (installed site-packages METADATA)
  // 4. requirements.txt (flat, need pipdeptree or pip-show to resolve tree)

  const poetryLockPath = join(dir, "poetry.lock");
  const pyprojectPath = join(dir, "pyproject.toml");
  const pipfileLockPath = join(dir, "Pipfile.lock");
  const pipfilePath = join(dir, "Pipfile");
  const requirementsPath = join(dir, "requirements.txt");

  // 1. poetry.lock + pyproject.toml
  try {
    const lockContent = await readFile(poetryLockPath, "utf-8");
    let pyprojectContent: string | null = null;
    try { pyprojectContent = await readFile(pyprojectPath, "utf-8"); } catch {}
    return parsePoetryLock(lockContent, poetryLockPath, pyprojectContent);
  } catch { /* not found, try next */ }

  // 2. Pipfile.lock (+ Pipfile for direct dep names)
  try {
    const lockContent = await readFile(pipfileLockPath, "utf-8");
    let pipfileContent: string | null = null;
    try { pipfileContent = await readFile(pipfilePath, "utf-8"); } catch {}
    return parsePipfileLock(lockContent, pipfileLockPath, pipfileContent);
  } catch { /* not found, try next */ }

  // 3. requirements.txt — try to resolve tree via pipdeptree or pip show
  try {
    const content = await readFile(requirementsPath, "utf-8");
    return await parseRequirementsWithTree(content, requirementsPath, dir);
  } catch { /* not found */ }

  return null;
}

// ═══════════════════════════════════════════════════════════════
// poetry.lock parser — richest source of Python dep info
// ═══════════════════════════════════════════════════════════════

function parsePoetryLock(lockContent: string, file: string, pyprojectContent: string | null): ParserResult {
  const deps: Dependency[] = [];

  // Extract direct dependency names from pyproject.toml
  const directNames = new Set<string>();
  if (pyprojectContent) {
    // [tool.poetry.dependencies] and [tool.poetry.dev-dependencies] / [tool.poetry.group.dev.dependencies]
    const depSectionRegex = /\[tool\.poetry(?:\.group\.\w+)?\.dependencies\]\s*\n([\s\S]*?)(?=\n\[|\n$)/g;
    let secMatch: RegExpExecArray | null;
    while ((secMatch = depSectionRegex.exec(pyprojectContent)) !== null) {
      const block = secMatch[1];
      for (const line of block.split("\n")) {
        const m = line.match(/^([a-zA-Z0-9_.-]+)\s*=/);
        if (m && m[1].toLowerCase() !== "python") {
          directNames.add(m[1].toLowerCase().replace(/-/g, "_"));
        }
      }
    }

    // Also try the PEP 621 style: [project] dependencies = [...]
    const pep621Match = pyprojectContent.match(/\[project\]\s*[\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]/);
    if (pep621Match) {
      const depsBlock = pep621Match[1];
      for (const line of depsBlock.split("\n")) {
        const m = line.match(/["']([a-zA-Z0-9_.-]+)/);
        if (m) directNames.add(m[1].toLowerCase().replace(/-/g, "_"));
      }
    }
  }

  // Parse [[package]] blocks in poetry.lock (TOML-like)
  const packageBlocks = lockContent.split(/\n\[\[package\]\]/);
  const allPkgs: Map<string, { name: string; version: string; deps: string[] }> = new Map();

  for (const block of packageBlocks) {
    const nameMatch = block.match(/^name\s*=\s*"([^"]+)"/m);
    const versionMatch = block.match(/^version\s*=\s*"([^"]+)"/m);
    if (!nameMatch || !versionMatch) continue;

    const pkgName = nameMatch[1].toLowerCase().replace(/-/g, "_");
    const version = versionMatch[1];

    // Extract [package.dependencies] section
    const depsSection = block.match(/\[package\.dependencies\]\s*\n([\s\S]*?)(?=\n\[|\n$)/);
    const pkgDeps: string[] = [];
    if (depsSection) {
      for (const line of depsSection[1].split("\n")) {
        const depMatch = line.match(/^([a-zA-Z0-9_.-]+)\s*=/);
        if (depMatch) {
          pkgDeps.push(depMatch[1].toLowerCase().replace(/-/g, "_"));
        }
      }
    }

    allPkgs.set(pkgName, { name: pkgName, version, deps: pkgDeps });
  }

  // If we have no directNames from pyproject.toml, treat all as direct (fallback)
  const hasDirectInfo = directNames.size > 0;

  // Build parent mapping: for each package, find which packages depend on it
  const parentOf: Map<string, string> = new Map();
  for (const [, pkg] of allPkgs) {
    for (const depName of pkg.deps) {
      if (!parentOf.has(depName)) {
        parentOf.set(depName, pkg.name);
      }
    }
  }

  for (const [, pkg] of allPkgs) {
    const isDirect = hasDirectInfo ? directNames.has(pkg.name) : true;
    const parent = isDirect ? undefined : parentOf.get(pkg.name);

    deps.push({
      name: pkg.name,
      version: pkg.version,
      ecosystem: "pip",
      isDirect,
      parent,
      purl: `pkg:pypi/${pkg.name}@${pkg.version}`,
    });
  }

  return { ecosystem: "pip", file, dependencies: deps };
}

// ═══════════════════════════════════════════════════════════════
// Pipfile.lock parser — cross-ref with Pipfile for direct deps
// ═══════════════════════════════════════════════════════════════

function parsePipfileLock(lockContent: string, file: string, pipfileContent: string | null): ParserResult {
  const lock = JSON.parse(lockContent);
  const deps: Dependency[] = [];

  // Extract direct dependency names from Pipfile
  const directNames = new Set<string>();
  if (pipfileContent) {
    // Parse [packages] and [dev-packages] sections
    const sections = ["packages", "dev-packages"];
    for (const section of sections) {
      const sectionRegex = new RegExp(`\\[${section}\\]\\s*\\n([\\s\\S]*?)(?=\\n\\[|$)`);
      const sectionMatch = pipfileContent.match(sectionRegex);
      if (sectionMatch) {
        for (const line of sectionMatch[1].split("\n")) {
          const m = line.match(/^([a-zA-Z0-9_.-]+)\s*=/);
          if (m) {
            directNames.add(m[1].toLowerCase().replace(/-/g, "_"));
          }
        }
      }
    }
  }

  const hasDirectInfo = directNames.size > 0;

  // Collect all packages first
  const allPkgNames: string[] = [];
  const allPkgData: Map<string, { name: string; version: string; section: string }> = new Map();

  for (const section of ["default", "develop"]) {
    const packages = lock[section];
    if (!packages) continue;

    for (const [name, info] of Object.entries(packages)) {
      const pkg = info as any;
      const version = (pkg.version || "").replace(/^==/, "");
      if (!version) continue;
      const normalized = name.toLowerCase().replace(/-/g, "_");
      allPkgNames.push(normalized);
      allPkgData.set(normalized, { name: normalized, version, section });
    }
  }

  for (const [normalized, pkg] of allPkgData) {
    // If we have Pipfile info, use it. Otherwise fall back: default = direct, develop = dev
    let isDirect: boolean;
    if (hasDirectInfo) {
      isDirect = directNames.has(normalized);
    } else {
      // Without Pipfile, we can't distinguish — mark all as direct (old behavior)
      isDirect = true;
    }

    deps.push({
      name: pkg.name,
      version: pkg.version,
      ecosystem: "pip",
      isDirect,
      scope: pkg.section === "develop" ? "dev" : "runtime",
      purl: `pkg:pypi/${pkg.name}@${pkg.version}`,
    });
  }

  return { ecosystem: "pip", file, dependencies: deps };
}

// ═══════════════════════════════════════════════════════════════
// requirements.txt parser — try pipdeptree for tree, else pip show
// ═══════════════════════════════════════════════════════════════

async function parseRequirementsWithTree(content: string, file: string, dir: string): Promise<ParserResult> {
  // First, parse the direct deps from requirements.txt
  const directDeps = parseRequirementsTxt(content);
  const directNames = new Set(directDeps.map(d => d.name));

  // Try pipdeptree for full dependency tree
  const treeDeps = await tryPipdeptree(dir, directNames);
  if (treeDeps && treeDeps.length > 0) {
    return { ecosystem: "pip", file, dependencies: treeDeps };
  }

  // Try pip show for individual package dependencies
  const enrichedDeps = await tryPipShow(dir, directDeps);
  if (enrichedDeps && enrichedDeps.length > directDeps.length) {
    return { ecosystem: "pip", file, dependencies: enrichedDeps };
  }

  // Fallback: try reading installed package metadata from venv/site-packages
  const metaDeps = await tryInstalledMetadata(dir, directDeps);
  if (metaDeps && metaDeps.length > directDeps.length) {
    return { ecosystem: "pip", file, dependencies: metaDeps };
  }

  // Last resort: return direct deps only
  return { ecosystem: "pip", file, dependencies: directDeps };
}

function parseRequirementsTxt(content: string): Dependency[] {
  const deps: Dependency[] = [];

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("-") || line.startsWith("http")) continue;

    // Handle: package==1.2.3, package>=1.2.3, package~=1.2.3
    const match = line.match(/^([a-zA-Z0-9._-]+)\s*[=~><!\[]+([\d][^\s;#,]*)?/);
    if (match) {
      const name = match[1].toLowerCase().replace(/-/g, "_");
      const version = match[2] || "unknown";
      deps.push({
        name,
        version,
        ecosystem: "pip",
        isDirect: true,
        purl: `pkg:pypi/${name}@${version}`,
      });
    } else if (line.match(/^[a-zA-Z0-9._-]+$/)) {
      deps.push({
        name: line.toLowerCase().replace(/-/g, "_"),
        version: "unknown",
        ecosystem: "pip",
        isDirect: true,
        purl: `pkg:pypi/${line.toLowerCase()}`,
      });
    }
  }

  return deps;
}

// ─── pipdeptree (best source of tree info for installed packages) ───

async function tryPipdeptree(dir: string, directNames: Set<string>): Promise<Dependency[] | null> {
  try {
    // Try venv-local pipdeptree first, then global
    const pythonPaths = [
      join(dir, ".venv", "bin", "python"),
      join(dir, "venv", "bin", "python"),
      join(dir, "env", "bin", "python"),
      "python3",
      "python",
    ];

    let jsonOutput: string | null = null;
    for (const py of pythonPaths) {
      try {
        jsonOutput = execSync(`${py} -m pipdeptree --json 2>/dev/null`, {
          cwd: dir,
          timeout: 15000,
          encoding: "utf-8",
        });
        if (jsonOutput) break;
      } catch { continue; }
    }

    if (!jsonOutput) return null;

    const tree = JSON.parse(jsonOutput) as Array<{
      package: { package_name: string; installed_version: string };
      dependencies: Array<{ package_name: string; installed_version: string; required_version: string }>;
    }>;

    const deps: Dependency[] = [];
    const seen = new Set<string>();

    for (const entry of tree) {
      const name = entry.package.package_name.toLowerCase().replace(/-/g, "_");
      const version = entry.package.installed_version;
      const isDirect = directNames.has(name);

      if (!seen.has(name)) {
        seen.add(name);
        deps.push({
          name,
          version,
          ecosystem: "pip",
          isDirect,
          purl: `pkg:pypi/${name}@${version}`,
        });
      }

      // Add transitive dependencies
      for (const child of entry.dependencies) {
        const childName = child.package_name.toLowerCase().replace(/-/g, "_");
        if (!seen.has(childName)) {
          seen.add(childName);
          deps.push({
            name: childName,
            version: child.installed_version,
            ecosystem: "pip",
            isDirect: directNames.has(childName),
            parent: name,
            purl: `pkg:pypi/${childName}@${child.installed_version}`,
          });
        }
      }
    }

    return deps.length > 0 ? deps : null;
  } catch {
    return null;
  }
}

// ─── pip show (fallback: query each direct dep for its requirements) ───

async function tryPipShow(dir: string, directDeps: Dependency[]): Promise<Dependency[] | null> {
  try {
    const pythonPaths = [
      join(dir, ".venv", "bin", "pip"),
      join(dir, "venv", "bin", "pip"),
      join(dir, "env", "bin", "pip"),
      "pip3",
      "pip",
    ];

    let pipCmd: string | null = null;
    for (const p of pythonPaths) {
      try {
        execSync(`${p} --version 2>/dev/null`, { timeout: 5000, encoding: "utf-8" });
        pipCmd = p;
        break;
      } catch { continue; }
    }
    if (!pipCmd) return null;

    const allDeps: Dependency[] = [...directDeps];
    const seen = new Set<string>(directDeps.map(d => d.name));
    const directNames = new Set<string>(directDeps.map(d => d.name));

    // Get all installed packages' info in a batch
    const allNames = directDeps.map(d => d.name).join(" ");
    let showOutput: string;
    try {
      showOutput = execSync(`${pipCmd} show ${allNames} 2>/dev/null`, {
        cwd: dir,
        timeout: 15000,
        encoding: "utf-8",
      });
    } catch { return null; }

    // Parse pip show output: blocks separated by "---"
    const blocks = showOutput.split("---");
    for (const block of blocks) {
      const nameMatch = block.match(/^Name:\s*(.+)/m);
      const versionMatch = block.match(/^Version:\s*(.+)/m);
      const requiresMatch = block.match(/^Requires:\s*(.+)/m);

      if (!nameMatch) continue;
      const pkgName = nameMatch[1].trim().toLowerCase().replace(/-/g, "_");

      if (requiresMatch) {
        const requires = requiresMatch[1].trim();
        if (requires) {
          for (const reqName of requires.split(",")) {
            const normalized = reqName.trim().toLowerCase().replace(/-/g, "_");
            if (normalized && !seen.has(normalized)) {
              seen.add(normalized);
              // Try to get version from a second pip show call
              let reqVersion = "unknown";
              try {
                const reqInfo = execSync(`${pipCmd} show ${normalized} 2>/dev/null`, {
                  cwd: dir,
                  timeout: 5000,
                  encoding: "utf-8",
                });
                const rv = reqInfo.match(/^Version:\s*(.+)/m);
                if (rv) reqVersion = rv[1].trim();
              } catch {}

              allDeps.push({
                name: normalized,
                version: reqVersion,
                ecosystem: "pip",
                isDirect: directNames.has(normalized),
                parent: pkgName,
                purl: `pkg:pypi/${normalized}@${reqVersion}`,
              });
            }
          }
        }
      }
    }

    return allDeps;
  } catch {
    return null;
  }
}

// ─── Installed metadata (read METADATA files from site-packages) ───

async function tryInstalledMetadata(dir: string, directDeps: Dependency[]): Promise<Dependency[] | null> {
  try {
    // Look for virtual environment site-packages
    const venvPaths = [
      join(dir, ".venv", "lib"),
      join(dir, "venv", "lib"),
      join(dir, "env", "lib"),
    ];

    let sitePackagesDir: string | null = null;
    for (const venvLib of venvPaths) {
      try {
        const pyDirs = await readdir(venvLib);
        for (const pyDir of pyDirs) {
          if (pyDir.startsWith("python")) {
            const candidate = join(venvLib, pyDir, "site-packages");
            try {
              await access(candidate);
              sitePackagesDir = candidate;
              break;
            } catch { continue; }
          }
        }
        if (sitePackagesDir) break;
      } catch { continue; }
    }

    if (!sitePackagesDir) return null;

    const entries = await readdir(sitePackagesDir);
    const distInfoDirs = entries.filter(e => e.endsWith(".dist-info"));

    const allDeps: Dependency[] = [];
    const directNames = new Set<string>(directDeps.map(d => d.name));
    const seen = new Set<string>();
    const pkgRequires: Map<string, string[]> = new Map();

    // Read all METADATA files to get version and dependencies
    for (const distDir of distInfoDirs) {
      const metadataPath = join(sitePackagesDir, distDir, "METADATA");
      try {
        const metadata = await readFile(metadataPath, "utf-8");
        const nameMatch = metadata.match(/^Name:\s*(.+)/m);
        const versionMatch = metadata.match(/^Version:\s*(.+)/m);
        if (!nameMatch || !versionMatch) continue;

        const name = nameMatch[1].trim().toLowerCase().replace(/-/g, "_");
        const version = versionMatch[1].trim();

        if (seen.has(name)) continue;
        seen.add(name);

        // Extract Requires-Dist entries
        const requires: string[] = [];
        const requiresRegex = /^Requires-Dist:\s*([a-zA-Z0-9_.-]+)/gm;
        let reqMatch: RegExpExecArray | null;
        while ((reqMatch = requiresRegex.exec(metadata)) !== null) {
          // Skip optional/extra dependencies (those with "; extra ==" markers)
          const fullLine = metadata.substring(reqMatch.index, metadata.indexOf("\n", reqMatch.index));
          if (fullLine.includes("extra ==")) continue;
          requires.push(reqMatch[1].toLowerCase().replace(/-/g, "_"));
        }

        pkgRequires.set(name, requires);

        allDeps.push({
          name,
          version,
          ecosystem: "pip",
          isDirect: directNames.has(name),
          purl: `pkg:pypi/${name}@${version}`,
        });
      } catch { continue; }
    }

    // Now set parent relationships
    for (const dep of allDeps) {
      if (!dep.isDirect) {
        // Find who depends on this package
        for (const [parentName, requires] of pkgRequires) {
          if (requires.includes(dep.name)) {
            dep.parent = parentName;
            break;
          }
        }
      }
    }

    return allDeps.length > directDeps.length ? allDeps : null;
  } catch {
    return null;
  }
}
