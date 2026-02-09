// ─── JSON File Store ───
// Persistent storage for scan history, vulnerability cache, and analytics
// Zero dependencies — works on Node.js AND Bun
// Data stored as JSON files in ~/.scato/

import { mkdirSync, existsSync, readFileSync, writeFileSync, readdirSync, unlinkSync } from "fs";
import { join } from "path";
import { randomUUID } from "crypto";
import type { ScanReport, VulnerabilitySource } from "../types.js";

function getDefaultDataDir(): string {
  const home = process.env.HOME || process.env.USERPROFILE || "/tmp";
  return process.env.SCATO_DATA_DIR || join(home, ".scato");
}

function ensureDir(dir: string): void {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

function readJSON<T>(path: string): T | null {
  try {
    if (!existsSync(path)) return null;
    return JSON.parse(readFileSync(path, "utf-8")) as T;
  } catch {
    return null;
  }
}

function writeJSON(path: string, data: unknown): void {
  writeFileSync(path, JSON.stringify(data, null, 2), "utf-8");
}

// ─── Scan Index Entry (lightweight, stored in index file) ───

interface ScanIndexEntry {
  id: string;
  target: string;
  timestamp: string;
  durationMs: number;
  totalDeps: number;
  totalVulns: number;
  riskScore: number;
  severityCounts: Record<string, number>;
  ecosystems: string[];
}

// ─── Cache Entry ───

interface CacheEntry {
  data: string;
  fetchedAt: string;
  expiresAt: string;
}

export class ScatoDatabase {
  private dataDir: string;
  private scansDir: string;
  private cacheDir: string;
  private indexPath: string;
  private index: ScanIndexEntry[];

  constructor(dataDir?: string) {
    this.dataDir = dataDir || getDefaultDataDir();
    this.scansDir = join(this.dataDir, "scans");
    this.cacheDir = join(this.dataDir, "cache");
    this.indexPath = join(this.dataDir, "scan-index.json");

    ensureDir(this.dataDir);
    ensureDir(this.scansDir);
    ensureDir(this.cacheDir);

    this.index = readJSON<ScanIndexEntry[]>(this.indexPath) || [];
  }

  private saveIndex(): void {
    writeJSON(this.indexPath, this.index);
  }

  // ─── Scan History ───

  saveScan(report: ScanReport): string {
    const id = report.scanId || randomUUID();

    // Save full report
    const reportPath = join(this.scansDir, `${id}.json`);
    writeJSON(reportPath, report);

    // Update index
    const entry: ScanIndexEntry = {
      id,
      target: report.target,
      timestamp: report.timestamp,
      durationMs: report.scanDurationMs || 0,
      totalDeps: report.totalDependencies,
      totalVulns: report.totalVulnerabilities,
      riskScore: report.metrics?.riskScore || 0,
      severityCounts: report.severityCounts,
      ecosystems: report.ecosystems,
    };

    this.index.unshift(entry);

    // Keep only last 500 scans in the index
    if (this.index.length > 500) {
      const removed = this.index.splice(500);
      for (const old of removed) {
        try {
          const oldPath = join(this.scansDir, `${old.id}.json`);
          if (existsSync(oldPath)) unlinkSync(oldPath);
        } catch { /* best effort cleanup */ }
      }
    }

    this.saveIndex();
    return id;
  }

  getRecentScans(target?: string, limit = 20): Array<{
    id: string;
    target: string;
    timestamp: string;
    totalDeps: number;
    totalVulns: number;
    riskScore: number;
  }> {
    let filtered = this.index;

    if (target) {
      filtered = filtered.filter((s) => s.target === target);
    }

    return filtered.slice(0, limit).map((s) => ({
      id: s.id,
      target: s.target,
      timestamp: s.timestamp,
      totalDeps: s.totalDeps,
      totalVulns: s.totalVulns,
      riskScore: s.riskScore,
    }));
  }

  getScanById(id: string): ScanReport | null {
    const reportPath = join(this.scansDir, `${id}.json`);
    return readJSON<ScanReport>(reportPath);
  }

  getLastScan(target: string): ScanReport | null {
    const entry = this.index.find((s) => s.target === target);
    if (!entry) return null;
    return this.getScanById(entry.id);
  }

  // ─── Trend Analysis ───

  getTrend(target: string, days = 30): Array<{
    date: string;
    totalVulns: number;
    riskScore: number;
    criticalCount: number;
    highCount: number;
  }> {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - days);
    const cutoffISO = cutoff.toISOString();

    return this.index
      .filter((s) => s.target === target && s.timestamp >= cutoffISO)
      .reverse() // oldest first
      .map((s) => ({
        date: s.timestamp.split("T")[0],
        totalVulns: s.totalVulns,
        riskScore: s.riskScore,
        criticalCount: s.severityCounts?.CRITICAL || 0,
        highCount: s.severityCounts?.HIGH || 0,
      }));
  }

  // ─── Vulnerability Cache ───

  getCachedVuln(id: string, source: VulnerabilitySource): string | null {
    const cachePath = join(this.cacheDir, `${source}_${encodeURIComponent(id)}.json`);
    const entry = readJSON<CacheEntry>(cachePath);
    if (!entry) return null;

    // Check expiry
    if (new Date(entry.expiresAt) <= new Date()) {
      try { unlinkSync(cachePath); } catch { /* ignore */ }
      return null;
    }

    return entry.data;
  }

  setCachedVuln(
    id: string,
    source: VulnerabilitySource,
    data: string,
    ttlHours = 24
  ): void {
    const now = new Date();
    const expires = new Date(now.getTime() + ttlHours * 60 * 60 * 1000);

    const cachePath = join(this.cacheDir, `${source}_${encodeURIComponent(id)}.json`);
    writeJSON(cachePath, {
      data,
      fetchedAt: now.toISOString(),
      expiresAt: expires.toISOString(),
    });
  }

  pruneExpiredCache(): number {
    let pruned = 0;
    try {
      const files = readdirSync(this.cacheDir);
      for (const file of files) {
        if (!file.endsWith(".json")) continue;
        const cachePath = join(this.cacheDir, file);
        const entry = readJSON<CacheEntry>(cachePath);
        if (entry && new Date(entry.expiresAt) <= new Date()) {
          unlinkSync(cachePath);
          pruned++;
        }
      }
    } catch { /* best effort */ }
    return pruned;
  }

  // ─── Analytics Queries ───

  getDependencyFrequency(limit = 20): Array<{
    name: string;
    ecosystem: string;
    scanCount: number;
    avgVulnCount: number;
  }> {
    const depMap = new Map<string, { name: string; ecosystem: string; scanIds: Set<string>; totalVulns: number }>();

    for (const entry of this.index) {
      const report = this.getScanById(entry.id);
      if (!report) continue;

      for (const result of report.results) {
        const key = `${result.dependency.ecosystem}:${result.dependency.name}`;
        if (!depMap.has(key)) {
          depMap.set(key, {
            name: result.dependency.name,
            ecosystem: result.dependency.ecosystem,
            scanIds: new Set(),
            totalVulns: 0,
          });
        }
        const d = depMap.get(key)!;
        d.scanIds.add(entry.id);
        d.totalVulns += result.vulnerabilities.length;
      }
    }

    return [...depMap.values()]
      .map((d) => ({
        name: d.name,
        ecosystem: d.ecosystem,
        scanCount: d.scanIds.size,
        avgVulnCount: d.totalVulns / d.scanIds.size,
      }))
      .sort((a, b) => b.scanCount - a.scanCount)
      .slice(0, limit);
  }

  getMostVulnerableDeps(limit = 10): Array<{
    name: string;
    ecosystem: string;
    version: string;
    vulnCount: number;
    lastSeen: string;
  }> {
    const results: Array<{
      name: string;
      ecosystem: string;
      version: string;
      vulnCount: number;
      lastSeen: string;
    }> = [];

    for (const entry of this.index) {
      const report = this.getScanById(entry.id);
      if (!report) continue;

      for (const result of report.results) {
        if (result.vulnerabilities.length > 0) {
          results.push({
            name: result.dependency.name,
            ecosystem: result.dependency.ecosystem,
            version: result.dependency.version,
            vulnCount: result.vulnerabilities.length,
            lastSeen: entry.timestamp,
          });
        }
      }
    }

    return results
      .sort((a, b) => b.vulnCount - a.vulnCount || b.lastSeen.localeCompare(a.lastSeen))
      .slice(0, limit);
  }

  close(): void {
    // No-op for JSON file store (no connection to close)
  }
}

// Singleton for convenience
let _instance: ScatoDatabase | null = null;

export function getDatabase(dataDir?: string): ScatoDatabase {
  if (!_instance) {
    _instance = new ScatoDatabase(dataDir);
  }
  return _instance;
}

export function closeDatabase(): void {
  if (_instance) {
    _instance.close();
    _instance = null;
  }
}
