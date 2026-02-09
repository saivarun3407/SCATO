import type { ScanReport } from "../../types.js";

export function formatJsonReport(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}
