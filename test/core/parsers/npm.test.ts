import { describe, test, expect } from "bun:test";
import { parseNpm } from "../../../src/core/parsers/npm.js";
import { resolve } from "path";

const FIXTURES = resolve(__dirname, "../../fixtures/npm");

describe("npm parser", () => {
  test("parses package-lock.json and returns ParserResult", async () => {
    const result = await parseNpm(FIXTURES);
    expect(result).not.toBeNull();
    expect(result!.ecosystem).toBe("npm");
    expect(result!.file).toContain("package-lock.json");
    expect(result!.dependencies.length).toBeGreaterThanOrEqual(3);
  });

  test("extracts correct version for direct dependencies", async () => {
    const result = await parseNpm(FIXTURES);
    const express = result!.dependencies.find((d) => d.name === "express");
    expect(express).toBeDefined();
    expect(express!.version).toBe("4.18.2");
    expect(express!.ecosystem).toBe("npm");

    const lodash = result!.dependencies.find((d) => d.name === "lodash");
    expect(lodash).toBeDefined();
    expect(lodash!.version).toBe("4.17.21");
  });

  test("identifies direct vs transitive dependencies", async () => {
    const result = await parseNpm(FIXTURES);
    const direct = result!.dependencies.filter((d) => d.isDirect);
    const transitive = result!.dependencies.filter((d) => !d.isDirect);
    expect(direct.length).toBeGreaterThanOrEqual(2);
    expect(transitive.length).toBeGreaterThanOrEqual(1);

    // express and lodash should be direct
    expect(direct.some((d) => d.name === "express")).toBe(true);
    expect(direct.some((d) => d.name === "lodash")).toBe(true);

    // body-parser, accepts, debug should be transitive
    expect(transitive.some((d) => d.name === "body-parser")).toBe(true);
    expect(transitive.some((d) => d.name === "accepts")).toBe(true);
    expect(transitive.some((d) => d.name === "debug")).toBe(true);
  });

  test("generates correct purl for dependencies", async () => {
    const result = await parseNpm(FIXTURES);
    const express = result!.dependencies.find((d) => d.name === "express");
    expect(express!.purl).toBe("pkg:npm/express@4.18.2");
  });

  test("includes license from lockfile when available", async () => {
    const result = await parseNpm(FIXTURES);
    const express = result!.dependencies.find((d) => d.name === "express");
    expect(express!.license).toBe("MIT");
  });

  test("returns null for directory with no npm files", async () => {
    const result = await parseNpm("/tmp/empty-dir-npm-test-" + Date.now());
    expect(result).toBeNull();
  });
});
