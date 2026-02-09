import { describe, test, expect } from "bun:test";
import {
  discoverDependencies,
  parseAllEcosystems,
} from "../../../src/core/parsers/index.js";
import { resolve } from "path";

const NPM_FIXTURES = resolve(__dirname, "../../fixtures/npm");
const PIP_FIXTURES = resolve(__dirname, "../../fixtures/pip");

describe("parseAllEcosystems", () => {
  test("discovers npm ecosystem from npm fixture directory", async () => {
    const results = await parseAllEcosystems(NPM_FIXTURES);
    expect(results.length).toBeGreaterThanOrEqual(1);
    const npmResult = results.find((r) => r.ecosystem === "npm");
    expect(npmResult).toBeDefined();
    expect(npmResult!.dependencies.length).toBeGreaterThanOrEqual(2);
  });

  test("discovers pip ecosystem from pip fixture directory", async () => {
    const results = await parseAllEcosystems(PIP_FIXTURES);
    const pipResult = results.find((r) => r.ecosystem === "pip");
    expect(pipResult).toBeDefined();
    expect(pipResult!.dependencies.length).toBeGreaterThanOrEqual(2);
  });

  test("returns empty array for directory with no manifest files", async () => {
    const results = await parseAllEcosystems(
      "/tmp/empty-dir-all-test-" + Date.now()
    );
    expect(results).toEqual([]);
  });
});

describe("discoverDependencies", () => {
  test("discovers npm dependencies from fixtures", async () => {
    const deps = await discoverDependencies(NPM_FIXTURES);
    expect(deps.length).toBeGreaterThanOrEqual(2);
    expect(deps.every((d) => d.ecosystem === "npm")).toBe(true);
  });

  test("filters by ecosystem - matching", async () => {
    const deps = await discoverDependencies(NPM_FIXTURES, {
      ecosystems: ["npm"],
    });
    expect(deps.length).toBeGreaterThanOrEqual(2);
    expect(deps.every((d) => d.ecosystem === "npm")).toBe(true);
  });

  test("filters by ecosystem - non-matching returns empty", async () => {
    const deps = await discoverDependencies(NPM_FIXTURES, {
      ecosystems: ["pip"],
    });
    expect(deps.length).toBe(0);
  });

  test("skips dev dependencies when requested", async () => {
    const deps = await discoverDependencies(NPM_FIXTURES, { skipDev: true });
    expect(deps.every((d) => d.scope !== "dev")).toBe(true);
  });

  test("returns all deps from pip fixtures", async () => {
    const deps = await discoverDependencies(PIP_FIXTURES);
    expect(deps.length).toBeGreaterThanOrEqual(2);
    expect(deps.every((d) => d.ecosystem === "pip")).toBe(true);

    const requests = deps.find((d) => d.name === "requests");
    expect(requests).toBeDefined();
    expect(requests!.version).toBe("2.31.0");
  });

  test("returns empty array for nonexistent directory", async () => {
    const deps = await discoverDependencies(
      "/tmp/empty-dir-discover-test-" + Date.now()
    );
    expect(deps.length).toBe(0);
  });
});
