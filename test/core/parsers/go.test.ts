import { describe, test, expect } from "bun:test";
import { parseGo } from "../../../src/core/parsers/go.js";
import { resolve } from "path";

const FIXTURES = resolve(__dirname, "../../fixtures/go");

describe("go parser", () => {
  test("parses go.sum and returns ParserResult", async () => {
    const result = await parseGo(FIXTURES);
    expect(result).not.toBeNull();
    expect(result!.ecosystem).toBe("go");
    expect(result!.file).toContain("go.sum");
    expect(result!.dependencies.length).toBeGreaterThanOrEqual(3);
  });

  test("extracts correct versions from go.sum", async () => {
    const result = await parseGo(FIXTURES);
    const gin = result!.dependencies.find(
      (d) => d.name === "github.com/gin-gonic/gin"
    );
    expect(gin).toBeDefined();
    expect(gin!.version).toBe("v1.9.1");
    expect(gin!.ecosystem).toBe("go");
  });

  test("deduplicates entries (skips /go.mod lines)", async () => {
    const result = await parseGo(FIXTURES);
    // go.sum has both h1: and /go.mod entries; parser should skip /go.mod
    const ginEntries = result!.dependencies.filter(
      (d) => d.name === "github.com/gin-gonic/gin"
    );
    expect(ginEntries.length).toBe(1);
  });

  test("identifies direct vs indirect dependencies using go.mod", async () => {
    const result = await parseGo(FIXTURES);

    // Direct deps (no // indirect comment in go.mod)
    const gin = result!.dependencies.find(
      (d) => d.name === "github.com/gin-gonic/gin"
    );
    expect(gin!.isDirect).toBe(true);

    const validator = result!.dependencies.find(
      (d) => d.name === "github.com/go-playground/validator/v10"
    );
    expect(validator!.isDirect).toBe(true);

    const crypto = result!.dependencies.find(
      (d) => d.name === "golang.org/x/crypto"
    );
    expect(crypto!.isDirect).toBe(true);

    // Indirect deps (marked // indirect in go.mod)
    const sonic = result!.dependencies.find(
      (d) => d.name === "github.com/bytedance/sonic"
    );
    expect(sonic!.isDirect).toBe(false);

    const mimetype = result!.dependencies.find(
      (d) => d.name === "github.com/gabriel-vasile/mimetype"
    );
    expect(mimetype!.isDirect).toBe(false);
  });

  test("generates correct purl for go modules", async () => {
    const result = await parseGo(FIXTURES);
    const gin = result!.dependencies.find(
      (d) => d.name === "github.com/gin-gonic/gin"
    );
    expect(gin!.purl).toBe("pkg:golang/github.com/gin-gonic/gin@v1.9.1");
  });

  test("returns null for directory with no go files", async () => {
    const result = await parseGo("/tmp/empty-dir-go-test-" + Date.now());
    expect(result).toBeNull();
  });
});
