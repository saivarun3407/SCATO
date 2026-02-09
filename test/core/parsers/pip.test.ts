import { describe, test, expect } from "bun:test";
import { parsePip } from "../../../src/core/parsers/pip.js";
import { resolve } from "path";
import { rename, rename as renameBack } from "fs/promises";

const FIXTURES = resolve(__dirname, "../../fixtures/pip");

describe("pip parser", () => {
  test("parses Pipfile.lock and returns ParserResult", async () => {
    const result = await parsePip(FIXTURES);
    expect(result).not.toBeNull();
    expect(result!.ecosystem).toBe("pip");
    expect(result!.file).toContain("Pipfile.lock");
    expect(result!.dependencies.length).toBe(5);
  });

  test("extracts correct versions from Pipfile.lock", async () => {
    const result = await parsePip(FIXTURES);
    const requests = result!.dependencies.find((d) => d.name === "requests");
    expect(requests).toBeDefined();
    expect(requests!.version).toBe("2.31.0");
    expect(requests!.ecosystem).toBe("pip");

    const flask = result!.dependencies.find((d) => d.name === "flask");
    expect(flask).toBeDefined();
    expect(flask!.version).toBe("3.0.0");
  });

  test("lowercases package names", async () => {
    const result = await parsePip(FIXTURES);
    for (const dep of result!.dependencies) {
      expect(dep.name).toBe(dep.name.toLowerCase());
    }
  });

  test("marks all default section deps as isDirect true", async () => {
    const result = await parsePip(FIXTURES);
    // All packages are in "default" section, so all isDirect
    for (const dep of result!.dependencies) {
      expect(dep.isDirect).toBe(true);
    }
  });

  test("includes transitive pip deps from Pipfile.lock", async () => {
    const result = await parsePip(FIXTURES);
    const urllib3 = result!.dependencies.find((d) => d.name === "urllib3");
    expect(urllib3).toBeDefined();
    expect(urllib3!.version).toBe("2.1.0");

    const certifi = result!.dependencies.find((d) => d.name === "certifi");
    expect(certifi).toBeDefined();
    expect(certifi!.version).toBe("2023.7.22");

    const charsetNorm = result!.dependencies.find(
      (d) => d.name === "charset-normalizer"
    );
    expect(charsetNorm).toBeDefined();
    expect(charsetNorm!.version).toBe("3.3.2");
  });

  test("generates correct purl for pip packages", async () => {
    const result = await parsePip(FIXTURES);
    const requests = result!.dependencies.find((d) => d.name === "requests");
    expect(requests!.purl).toBe("pkg:pypi/requests@2.31.0");
  });

  test("falls back to requirements.txt when Pipfile.lock is absent", async () => {
    // Temporarily move Pipfile.lock out of the way
    const lockPath = resolve(FIXTURES, "Pipfile.lock");
    const tmpPath = resolve(FIXTURES, "Pipfile.lock.bak");
    await rename(lockPath, tmpPath);

    try {
      const result = await parsePip(FIXTURES);
      expect(result).not.toBeNull();
      expect(result!.ecosystem).toBe("pip");
      expect(result!.file).toContain("requirements.txt");
      expect(result!.dependencies.length).toBe(2);

      const requests = result!.dependencies.find((d) => d.name === "requests");
      expect(requests).toBeDefined();
      expect(requests!.version).toBe("2.31.0");
      expect(requests!.isDirect).toBe(true);
    } finally {
      await renameBack(tmpPath, lockPath);
    }
  });

  test("returns null for directory with no pip files", async () => {
    const result = await parsePip("/tmp/empty-dir-pip-test-" + Date.now());
    expect(result).toBeNull();
  });
});
