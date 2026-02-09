// ─── SCATO Web Server ───
// Built-in HTTP server for the REST API and web dashboard
// Uses Hono — works on Node.js AND Bun

import { Hono } from "hono";
import { cors } from "hono/cors";
import { resolve } from "path";
import { scan } from "./scanner.js";
import { getDatabase, closeDatabase } from "./storage/database.js";
import { getDashboardHTML } from "./web/dashboard.js";
import type { Ecosystem, VulnerabilitySource } from "./types.js";

const VERSION = "3.0.0";

export function createApp(): Hono {
  const app = new Hono();

  // ─── Middleware ───
  app.use("/api/*", cors());

  // ─── Dashboard (serves the built-in web UI) ───
  app.get("/", (c) => {
    c.header("Cache-Control", "no-store, no-cache, must-revalidate");
    c.header("Pragma", "no-cache");
    return c.html(getDashboardHTML());
  });

  // ─── API: Health ───
  app.get("/api/health", (c) => {
    return c.json({
      status: "ok",
      tool: "scato",
      version: VERSION,
      timestamp: new Date().toISOString(),
    });
  });

  // ─── API: Trigger Scan ───
  app.post("/api/scan", async (c) => {
    try {
      const body = await c.req.json().catch(() => ({}));
      const target = resolve(body.target || body.directory || ".");
      const ecosystems = body.ecosystems as Ecosystem[] | undefined;
      const sources = body.sources as VulnerabilitySource[] | undefined;

      const report = await scan({
        target,
        ecosystems,
        sources,
        skipLicenses: body.skipLicenses ?? false,
        skipDev: body.skipDev ?? false,
        sbomOutput: body.sbomOutput,
        sbomFormat: body.sbomFormat,
        sarifOutput: body.sarifOutput,
        nvdApiKey: body.nvdApiKey || process.env.NVD_API_KEY,
        githubToken: body.githubToken || process.env.GITHUB_TOKEN,
        policyFile: body.policyFile,
        offlineMode: body.offlineMode ?? false,
      });

      return c.json(report);
    } catch (err: any) {
      return c.json({ error: err.message || String(err) }, 500);
    }
  });

  // ─── API: List Scan History ───
  app.get("/api/scans", (c) => {
    try {
      const target = c.req.query("target");
      const limit = parseInt(c.req.query("limit") || "20", 10);
      const db = getDatabase();
      const scans = db.getRecentScans(target || undefined, limit);
      return c.json({ scans });
    } catch (err: any) {
      return c.json({ error: err.message || String(err) }, 500);
    }
  });

  // ─── API: Get Scan by ID ───
  app.get("/api/scans/:id", (c) => {
    try {
      const db = getDatabase();
      const report = db.getScanById(c.req.param("id"));
      if (!report) {
        return c.json({ error: "Scan not found" }, 404);
      }
      return c.json(report);
    } catch (err: any) {
      return c.json({ error: err.message || String(err) }, 500);
    }
  });

  // ─── API: Package info (description, latest version) from registry ───
  app.get("/api/package-info", async (c) => {
    try {
      const ecosystem = c.req.query("ecosystem") || "";
      const name = c.req.query("name") || "";
      if (!name || !ecosystem) {
        return c.json({ error: "ecosystem and name are required" }, 400);
      }
      const safeName = encodeURIComponent(name);
      let description = "";
      let latestVersion = "";

      if (ecosystem === "npm") {
        const res = await fetch(`https://registry.npmjs.org/${safeName}`);
        if (res.ok) {
          const data = (await res.json()) as { description?: string; "dist-tags"?: { latest?: string } };
          description = data.description || "";
          latestVersion = data["dist-tags"]?.latest || "";
        }
      } else if (ecosystem === "pip") {
        const res = await fetch(`https://pypi.org/pypi/${safeName}/json`);
        if (res.ok) {
          const data = (await res.json()) as { info?: { summary?: string; version?: string } };
          description = data.info?.summary || "";
          latestVersion = data.info?.version || "";
        }
      }

      return c.json({ description, latestVersion });
    } catch (err: any) {
      return c.json({ error: err.message || String(err) }, 500);
    }
  });

  // ─── API: Get Trend ───
  app.get("/api/trend", (c) => {
    try {
      const target = c.req.query("target");
      const days = parseInt(c.req.query("days") || "30", 10);
      if (!target) {
        return c.json({ error: "target query parameter is required" }, 400);
      }
      const db = getDatabase();
      const trend = db.getTrend(target, days);
      return c.json({ trend });
    } catch (err: any) {
      return c.json({ error: err.message || String(err) }, 500);
    }
  });

  return app;
}

// ─── Start Server (callable from CLI or directly) ───

export async function startServer(options: { port?: number; open?: boolean } = {}): Promise<void> {
  const port = options.port || parseInt(process.env.SCATO_PORT || "3001", 10);
  const app = createApp();

  // Detect runtime and start accordingly
  const isBun = typeof globalThis.Bun !== "undefined";

  if (isBun) {
    // Bun native server
    const server = Bun.serve({
      port,
      fetch: app.fetch,
    });
    console.log(`\n  SCATO Dashboard running at http://localhost:${server.port}\n`);
  } else {
    // Node.js via @hono/node-server
    const { serve } = await import("@hono/node-server");
    serve({ fetch: app.fetch, port }, () => {
      console.log(`\n  SCATO Dashboard running at http://localhost:${port}\n`);
    });
  }

  // Auto-open browser if requested
  if (options.open) {
    const url = `http://localhost:${port}`;
    try {
      const { platform } = await import("os");
      const { exec } = await import("child_process");
      const cmd = platform() === "darwin" ? "open" : platform() === "win32" ? "start" : "xdg-open";
      exec(`${cmd} ${url}`);
    } catch { /* best effort */ }
  }

  // Graceful shutdown
  const shutdown = () => {
    closeDatabase();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
