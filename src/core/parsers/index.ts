import { parseNpm } from "./npm.js";
import { parsePip } from "./pip.js";
import { parseGo } from "./go.js";
import { parseMaven } from "./maven.js";
import { parseCargo } from "./cargo.js";
import type { Dependency, Ecosystem, ParserResult } from "../../types.js";

const PARSERS = [
  { name: "npm" as Ecosystem, parse: parseNpm },
  { name: "pip" as Ecosystem, parse: parsePip },
  { name: "go" as Ecosystem, parse: parseGo },
  { name: "maven" as Ecosystem, parse: parseMaven },
  { name: "cargo" as Ecosystem, parse: parseCargo },
] as const;

/**
 * Parse all ecosystems in a directory (backward compatible).
 */
export async function parseAllEcosystems(dir: string): Promise<ParserResult[]> {
  const results = await Promise.all(
    PARSERS.map(async ({ parse }) => {
      try {
        return await parse(dir);
      } catch (err) {
        // Silently skip ecosystems that fail to parse
        return null;
      }
    })
  );

  return results.filter((r): r is ParserResult => r !== null && r.dependencies.length > 0);
}

/**
 * Discover dependencies in a directory with filtering options.
 * New CORE layer API — runs all parsers in parallel, filters by ecosystem and dev deps.
 */
export async function discoverDependencies(
  dir: string,
  options: { ecosystems?: Ecosystem[]; skipDev?: boolean } = {}
): Promise<Dependency[]> {
  const parsersToRun = options.ecosystems
    ? PARSERS.filter((p) => options.ecosystems!.includes(p.name))
    : PARSERS;

  const results = await Promise.all(
    parsersToRun.map(async ({ parse }) => {
      try {
        return await parse(dir);
      } catch {
        return null;
      }
    })
  );

  const allDeps: Dependency[] = [];

  for (const result of results) {
    if (!result || result.dependencies.length === 0) continue;

    for (const dep of result.dependencies) {
      if (options.skipDev && dep.scope === "dev") continue;
      allDeps.push(dep);
    }
  }

  return allDeps;
}

// Re-export individual parsers for direct use
export { parseNpm } from "./npm.js";
export { parsePip } from "./pip.js";
export { parseGo } from "./go.js";
export { parseMaven } from "./maven.js";
export { parseCargo } from "./cargo.js";
