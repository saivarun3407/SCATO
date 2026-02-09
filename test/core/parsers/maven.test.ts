import { describe, test, expect } from "bun:test";
import { parseMaven } from "../../../src/core/parsers/maven.js";
import { resolve } from "path";

const FIXTURES = resolve(__dirname, "../../fixtures/maven");

describe("maven parser", () => {
  test("parses pom.xml and returns ParserResult", async () => {
    const result = await parseMaven(FIXTURES);
    expect(result).not.toBeNull();
    expect(result!.ecosystem).toBe("maven");
    expect(result!.file).toContain("pom.xml");
    expect(result!.dependencies.length).toBe(2);
  });

  test("extracts correct groupId:artifactId names", async () => {
    const result = await parseMaven(FIXTURES);
    const springCore = result!.dependencies.find(
      (d) => d.name === "org.springframework:spring-core"
    );
    expect(springCore).toBeDefined();

    const jackson = result!.dependencies.find(
      (d) => d.name === "com.fasterxml.jackson.core:jackson-databind"
    );
    expect(jackson).toBeDefined();
  });

  test("resolves property placeholders in versions", async () => {
    const result = await parseMaven(FIXTURES);
    // spring-core uses ${spring.version} which should resolve to 6.1.1
    const springCore = result!.dependencies.find(
      (d) => d.name === "org.springframework:spring-core"
    );
    expect(springCore!.version).toBe("6.1.1");
  });

  test("extracts literal versions correctly", async () => {
    const result = await parseMaven(FIXTURES);
    const jackson = result!.dependencies.find(
      (d) => d.name === "com.fasterxml.jackson.core:jackson-databind"
    );
    expect(jackson!.version).toBe("2.16.0");
  });

  test("marks all dependencies as direct", async () => {
    const result = await parseMaven(FIXTURES);
    for (const dep of result!.dependencies) {
      expect(dep.isDirect).toBe(true);
    }
  });

  test("generates correct purl for maven artifacts", async () => {
    const result = await parseMaven(FIXTURES);
    const jackson = result!.dependencies.find(
      (d) => d.name === "com.fasterxml.jackson.core:jackson-databind"
    );
    expect(jackson!.purl).toBe(
      "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.16.0"
    );
  });

  test("returns null for directory with no pom.xml", async () => {
    const result = await parseMaven("/tmp/empty-dir-maven-test-" + Date.now());
    expect(result).toBeNull();
  });
});
