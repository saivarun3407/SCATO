import type { Dependency, LicenseInfo } from "../../types.js";

// Well-known SPDX licenses and their properties
const LICENSE_DB: Record<string, Omit<LicenseInfo, "name">> = {
  "MIT": { spdxId: "MIT", isOsiApproved: true, isCopyleft: false, risk: "low" },
  "Apache-2.0": { spdxId: "Apache-2.0", isOsiApproved: true, isCopyleft: false, risk: "low" },
  "BSD-2-Clause": { spdxId: "BSD-2-Clause", isOsiApproved: true, isCopyleft: false, risk: "low" },
  "BSD-3-Clause": { spdxId: "BSD-3-Clause", isOsiApproved: true, isCopyleft: false, risk: "low" },
  "ISC": { spdxId: "ISC", isOsiApproved: true, isCopyleft: false, risk: "low" },
  "0BSD": { spdxId: "0BSD", isOsiApproved: true, isCopyleft: false, risk: "low" },
  "Unlicense": { spdxId: "Unlicense", isOsiApproved: true, isCopyleft: false, risk: "low" },
  "CC0-1.0": { spdxId: "CC0-1.0", isOsiApproved: false, isCopyleft: false, risk: "low" },
  "MPL-2.0": { spdxId: "MPL-2.0", isOsiApproved: true, isCopyleft: true, risk: "medium" },
  "LGPL-2.1": { spdxId: "LGPL-2.1-only", isOsiApproved: true, isCopyleft: true, risk: "medium" },
  "LGPL-3.0": { spdxId: "LGPL-3.0-only", isOsiApproved: true, isCopyleft: true, risk: "medium" },
  "GPL-2.0": { spdxId: "GPL-2.0-only", isOsiApproved: true, isCopyleft: true, risk: "high" },
  "GPL-3.0": { spdxId: "GPL-3.0-only", isOsiApproved: true, isCopyleft: true, risk: "high" },
  "AGPL-3.0": { spdxId: "AGPL-3.0-only", isOsiApproved: true, isCopyleft: true, risk: "high" },
  "SSPL-1.0": { spdxId: "SSPL-1.0", isOsiApproved: false, isCopyleft: true, risk: "high" },
  "BSL-1.0": { spdxId: "BSL-1.0", isOsiApproved: true, isCopyleft: false, risk: "low" },
};

// Normalize license strings to SPDX
const LICENSE_ALIASES: Record<string, string> = {
  "mit": "MIT",
  "apache 2.0": "Apache-2.0",
  "apache-2.0": "Apache-2.0",
  "apache2": "Apache-2.0",
  "bsd": "BSD-3-Clause",
  "bsd-2": "BSD-2-Clause",
  "bsd-3": "BSD-3-Clause",
  "isc": "ISC",
  "gpl": "GPL-3.0",
  "gpl-2": "GPL-2.0",
  "gpl-2.0": "GPL-2.0",
  "gpl-3": "GPL-3.0",
  "gpl-3.0": "GPL-3.0",
  "gplv2": "GPL-2.0",
  "gplv3": "GPL-3.0",
  "lgpl": "LGPL-3.0",
  "lgpl-2.1": "LGPL-2.1",
  "lgpl-3.0": "LGPL-3.0",
  "agpl": "AGPL-3.0",
  "agpl-3.0": "AGPL-3.0",
  "mpl": "MPL-2.0",
  "mpl-2.0": "MPL-2.0",
  "unlicense": "Unlicense",
  "cc0": "CC0-1.0",
  "cc0-1.0": "CC0-1.0",
  "0bsd": "0BSD",
  "(mit)": "MIT",
  "apache license 2.0": "Apache-2.0",
};

export function detectLicense(raw: string | undefined): LicenseInfo | null {
  if (!raw) return null;

  const normalized = raw.trim().toLowerCase();
  const spdxKey = LICENSE_ALIASES[normalized] || raw.trim();
  const info = LICENSE_DB[spdxKey];

  if (info) {
    return { name: spdxKey, ...info };
  }

  // Try partial match
  for (const [alias, spdx] of Object.entries(LICENSE_ALIASES)) {
    if (normalized.includes(alias)) {
      const matched = LICENSE_DB[spdx];
      if (matched) return { name: spdx, ...matched };
    }
  }

  return {
    name: raw.trim(),
    spdxId: raw.trim(),
    isOsiApproved: false,
    isCopyleft: false,
    risk: "medium", // Unknown license = medium risk
  };
}

export async function enrichLicenses(deps: Dependency[]): Promise<void> {
  // For npm packages, try to fetch license from the npm registry
  const npmDeps = deps.filter((d) => d.ecosystem === "npm" && !d.license);

  // Batch fetch license info (limit concurrency)
  const CONCURRENCY = 10;
  for (let i = 0; i < npmDeps.length; i += CONCURRENCY) {
    const batch = npmDeps.slice(i, i + CONCURRENCY);
    await Promise.all(
      batch.map(async (dep) => {
        try {
          const res = await fetch(
            `https://registry.npmjs.org/${encodeURIComponent(dep.name)}/${dep.version}`,
            { signal: AbortSignal.timeout(5000) }
          );
          if (res.ok) {
            const data = await res.json() as any;
            dep.license = typeof data.license === "string"
              ? data.license
              : data.license?.type || undefined;
          }
        } catch {
          // Silently skip - license enrichment is best-effort
        }
      })
    );
  }

  // For PyPI packages
  const pypiDeps = deps.filter((d) => d.ecosystem === "pip" && !d.license);
  for (let i = 0; i < pypiDeps.length; i += CONCURRENCY) {
    const batch = pypiDeps.slice(i, i + CONCURRENCY);
    await Promise.all(
      batch.map(async (dep) => {
        try {
          const res = await fetch(
            `https://pypi.org/pypi/${dep.name}/${dep.version}/json`,
            { signal: AbortSignal.timeout(5000) }
          );
          if (res.ok) {
            const data = await res.json() as any;
            dep.license = data.info?.license || undefined;
            // Sometimes PyPI puts the classifier instead
            if (!dep.license || dep.license === "UNKNOWN") {
              const classifiers: string[] = data.info?.classifiers || [];
              const licClassifier = classifiers.find((c: string) =>
                c.startsWith("License :: OSI Approved ::")
              );
              if (licClassifier) {
                dep.license = licClassifier.split("::").pop()?.trim();
              }
            }
          }
        } catch {
          // Best-effort
        }
      })
    );
  }
}
