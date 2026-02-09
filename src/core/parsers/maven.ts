import { readFile } from "fs/promises";
import { join } from "path";
import { execFileSync } from "child_process";
import { XMLParser } from "fast-xml-parser";
import type { Dependency, ParserResult } from "../../types.js";

export async function parseMaven(dir: string): Promise<ParserResult | null> {
  const pomPath = join(dir, "pom.xml");
  const gradleLockPath = join(dir, "gradle.lockfile");
  const buildGradlePath = join(dir, "build.gradle");
  const buildGradleKtsPath = join(dir, "build.gradle.kts");

  // 1. Try pom.xml + mvn dependency:tree for full transitive tree
  try {
    const content = await readFile(pomPath, "utf-8");
    const treeOutput = tryMvnDependencyTree(dir);
    return parsePom(content, pomPath, treeOutput);
  } catch { /* not found, try Gradle */ }

  // 2. Try gradle.lockfile (has all resolved dependencies)
  try {
    const lockContent = await readFile(gradleLockPath, "utf-8");
    const gradleTree = tryGradleDependencyTree(dir);
    return parseGradleLockfile(lockContent, gradleLockPath, gradleTree);
  } catch { /* not found */ }

  // 3. Try build.gradle or build.gradle.kts (direct deps only, + gradle dependencies)
  for (const gradlePath of [buildGradlePath, buildGradleKtsPath]) {
    try {
      const content = await readFile(gradlePath, "utf-8");
      const gradleTree = tryGradleDependencyTree(dir);
      return parseBuildGradle(content, gradlePath, gradleTree);
    } catch { continue; }
  }

  return null;
}

// ═══════════════════════════════════════════════════════════════
// Maven: pom.xml + mvn dependency:tree
// ═══════════════════════════════════════════════════════════════

/** Run `mvn dependency:tree` for full transitive dependency graph */
function tryMvnDependencyTree(dir: string): string {
  try {
    // OWASP CWE-78: use execFileSync (no shell) with args as array
    // Try mvnw first (Maven Wrapper), then global mvn
    const executables = [
      join(dir, "mvnw"),
      "mvn",
    ];
    const args = ["dependency:tree", "-DoutputType=text"];
    for (const exe of executables) {
      try {
        return execFileSync(exe, args, {
          cwd: dir,
          timeout: 60000,
          encoding: "utf-8",
          stdio: ["pipe", "pipe", "pipe"],
        });
      } catch { continue; }
    }
  } catch {}
  return "";
}

/** Parse the text output of mvn dependency:tree */
function parseMvnTreeOutput(output: string): { name: string; version: string; parent?: string; scope?: string }[] {
  const results: { name: string; version: string; parent?: string; scope?: string }[] = [];
  if (!output) return results;

  // Lines look like:
  // [INFO] com.example:myapp:jar:1.0
  // [INFO] +- org.springframework:spring-core:jar:5.3.20:compile
  // [INFO] |  +- org.springframework:spring-jcl:jar:5.3.20:compile
  // [INFO] \- junit:junit:jar:4.13.2:test

  const lines = output.split("\n");
  const parentStack: string[] = [];

  for (const line of lines) {
    // Remove [INFO] prefix
    const clean = line.replace(/^\[INFO\]\s*/, "");
    if (!clean || clean.startsWith("---") || clean.startsWith("BUILD") || clean.startsWith("Downloading")) continue;

    // Calculate depth from tree characters
    const treeMatch = clean.match(/^([| \\+-]*)\s*([\w.-]+):([\w.-]+):([\w.-]+):([\w.-]+)(?::([\w.-]+))?/);
    if (!treeMatch) {
      // Root project line: groupId:artifactId:packaging:version
      const rootMatch = clean.match(/^([\w.-]+):([\w.-]+):([\w.-]+):([\w.-]+)$/);
      if (rootMatch) {
        parentStack.length = 0;
        parentStack.push(`${rootMatch[1]}:${rootMatch[2]}`);
      }
      continue;
    }

    const prefix = treeMatch[1];
    const groupId = treeMatch[2];
    const artifactId = treeMatch[3];
    // treeMatch[4] is packaging (jar, war, etc.)
    const version = treeMatch[5];
    const scope = treeMatch[6] || "compile";
    const name = `${groupId}:${artifactId}`;

    // Calculate depth based on prefix length
    const depth = Math.floor(prefix.replace(/[^|+-\\]/g, "").length / 1) || 0;

    // Adjust parent stack
    while (parentStack.length > depth + 1) parentStack.pop();
    const parent = parentStack.length > 0 ? parentStack[parentStack.length - 1] : undefined;
    parentStack.push(name);

    results.push({ name, version, parent: depth === 0 ? undefined : parent, scope });
  }

  return results;
}

function parsePom(content: string, file: string, treeOutput: string): ParserResult {
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
  if (project.version) {
    properties["project.version"] = String(project.version);
  }

  // Get direct dependency names from pom.xml
  const directNames = new Set<string>();
  const directDeps = project.dependencies?.dependency || [];
  for (const dep of Array.isArray(directDeps) ? directDeps : [directDeps]) {
    if (!dep || !dep.groupId || !dep.artifactId) continue;
    directNames.add(`${dep.groupId}:${dep.artifactId}`);
  }

  // If we have mvn dependency:tree output, use it for full tree
  const treeEntries = parseMvnTreeOutput(treeOutput);
  if (treeEntries.length > 0) {
    const seen = new Set<string>();
    for (const entry of treeEntries) {
      if (seen.has(entry.name)) continue;
      seen.add(entry.name);
      const isDirect = directNames.has(entry.name);
      deps.push({
        name: entry.name,
        version: entry.version,
        ecosystem: "maven",
        isDirect,
        parent: isDirect ? undefined : entry.parent,
        scope: entry.scope === "test" ? "dev" : "runtime",
        purl: `pkg:maven/${entry.name.replace(":", "/")}@${entry.version}`,
      });
    }
    return { ecosystem: "maven", file, dependencies: deps };
  }

  // Fallback: parse pom.xml only (direct + dependencyManagement)
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
      scope: dep.scope === "test" ? "dev" : "runtime",
      purl: `pkg:maven/${groupId}/${artifactId}@${version}`,
    });
  }

  // Parse dependency management (often in parent POMs)
  const mgmtDeps = project.dependencyManagement?.dependencies?.dependency || [];
  for (const dep of Array.isArray(mgmtDeps) ? mgmtDeps : [mgmtDeps]) {
    if (!dep || !dep.groupId || !dep.artifactId) continue;
    const version = resolveProperty(String(dep.version || "unknown"), properties);
    const groupId = String(dep.groupId);
    const artifactId = String(dep.artifactId);
    const key = `${groupId}:${artifactId}`;

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

// ═══════════════════════════════════════════════════════════════
// Gradle: gradle.lockfile + build.gradle / build.gradle.kts
// ═══════════════════════════════════════════════════════════════

/** Run `gradle dependencies` for tree output */
function tryGradleDependencyTree(dir: string): string {
  try {
    // OWASP CWE-78: use execFileSync (no shell) with args as array
    const executables = [
      join(dir, "gradlew"),
      "gradle",
    ];
    const args = ["dependencies", "--configuration", "runtimeClasspath"];
    for (const exe of executables) {
      try {
        return execFileSync(exe, args, {
          cwd: dir,
          timeout: 60000,
          encoding: "utf-8",
          stdio: ["pipe", "pipe", "pipe"],
        });
      } catch { continue; }
    }
  } catch {}
  return "";
}

/** Parse gradle dependency tree output */
function parseGradleTreeOutput(output: string): { name: string; version: string; parent?: string }[] {
  const results: { name: string; version: string; parent?: string }[] = [];
  if (!output) return results;

  // Gradle tree format:
  // +--- org.springframework.boot:spring-boot-starter-web:3.1.0
  // |    +--- org.springframework.boot:spring-boot-starter:3.1.0
  // |    |    +--- org.springframework.boot:spring-boot:3.1.0
  // \--- org.projectlombok:lombok:1.18.28

  const parentStack: { name: string; depth: number }[] = [];

  for (const line of output.split("\n")) {
    // Match dependency lines with tree characters
    const match = line.match(/^([| \\+\-]*)\s*([\w.-]+):([\w.-]+):([\w.-]+)/);
    if (!match) continue;

    const prefix = match[1];
    const groupId = match[2];
    const artifactId = match[3];
    let version = match[4];
    // Strip " -> x.y.z" version overrides and " (*)" duplicates
    version = version.replace(/\s*->.*$/, "").replace(/\s*\(\*\).*$/, "");
    const name = `${groupId}:${artifactId}`;

    // Calculate depth from prefix
    const depth = Math.floor(prefix.length / 5);

    // Find parent
    while (parentStack.length > 0 && parentStack[parentStack.length - 1].depth >= depth) {
      parentStack.pop();
    }
    const parent = parentStack.length > 0 ? parentStack[parentStack.length - 1].name : undefined;
    parentStack.push({ name, depth });

    results.push({ name, version, parent: depth === 0 ? undefined : parent });
  }

  return results;
}

function parseGradleLockfile(content: string, file: string, treeOutput: string): ParserResult {
  const deps: Dependency[] = [];
  const treeEntries = parseGradleTreeOutput(treeOutput);

  // Build a map of name -> tree entry for parent info
  const treeMap = new Map<string, { parent?: string }>();
  const directFromTree = new Set<string>();
  for (const entry of treeEntries) {
    if (!treeMap.has(entry.name)) {
      treeMap.set(entry.name, { parent: entry.parent });
    }
    if (!entry.parent) directFromTree.add(entry.name);
  }

  // Parse gradle.lockfile: format is "group:artifact:version=configuration"
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("empty=")) continue;

    const match = trimmed.match(/^([\w.-]+):([\w.-]+):([\w.-]+)=/);
    if (!match) continue;

    const name = `${match[1]}:${match[2]}`;
    const version = match[3];
    const treeInfo = treeMap.get(name);
    const isDirect = directFromTree.has(name) || (!treeInfo && treeEntries.length === 0);

    deps.push({
      name,
      version,
      ecosystem: "maven",
      isDirect,
      parent: isDirect ? undefined : treeInfo?.parent,
      purl: `pkg:maven/${match[1]}/${match[2]}@${version}`,
    });
  }

  return { ecosystem: "maven", file, dependencies: deps };
}

function parseBuildGradle(content: string, file: string, treeOutput: string): ParserResult {
  const deps: Dependency[] = [];

  // If we have gradle tree output, use it (much richer)
  const treeEntries = parseGradleTreeOutput(treeOutput);
  if (treeEntries.length > 0) {
    const seen = new Set<string>();
    const directNames = new Set<string>(treeEntries.filter(e => !e.parent).map(e => e.name));
    for (const entry of treeEntries) {
      if (seen.has(entry.name)) continue;
      seen.add(entry.name);
      const isDirect = directNames.has(entry.name);
      deps.push({
        name: entry.name,
        version: entry.version,
        ecosystem: "maven",
        isDirect,
        parent: isDirect ? undefined : entry.parent,
        purl: `pkg:maven/${entry.name.replace(":", "/")}@${entry.version}`,
      });
    }
    return { ecosystem: "maven", file, dependencies: deps };
  }

  // Fallback: parse build.gradle for declared dependencies
  // Patterns: implementation 'group:artifact:version', api "group:artifact:version"
  const depPatterns = [
    /(?:implementation|api|compile|runtimeOnly|compileOnly|testImplementation)\s+['"]([^'"]+)['"]/g,
    /(?:implementation|api|compile|runtimeOnly|compileOnly|testImplementation)\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];

  const seen = new Set<string>();
  for (const pattern of depPatterns) {
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const parts = match[1].split(":");
      if (parts.length < 3) continue;
      const name = `${parts[0]}:${parts[1]}`;
      const version = parts[2];
      if (seen.has(name)) continue;
      seen.add(name);

      deps.push({
        name,
        version,
        ecosystem: "maven",
        isDirect: true,
        purl: `pkg:maven/${parts[0]}/${parts[1]}@${version}`,
      });
    }
  }

  return { ecosystem: "maven", file, dependencies: deps };
}
