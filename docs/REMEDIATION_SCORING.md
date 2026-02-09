# Prioritized Remediation — Scoring Algorithm

This document describes the exact calculation used by the **Prioritized Remediation Plan** to score each vulnerability and rank packages for fix priority. The model addresses the **"sum of lows" fallacy** (packages with many low-severity CVEs no longer eclipse a single Critical) and **aligns ROI % with ranking** via a KEV multiplier.

---

## 1. Per-CVE score (max 100 points per vulnerability)

Each CVE receives a **threat score** from five components. The weights sum to **100**:

| Component | Weight | Max points | How it's calculated |
|-----------|--------|------------|---------------------|
| **KEV** (CISA Known Exploited) | 30 | 30 | Binary: **30** if `isKnownExploited === true`, else **0** |
| **EPSS** (Exploit Prediction) | 20 | 20 | **epssScore × 20** (epssScore is 0.0–1.0) |
| **CVSS Vector** | 15 | 15 | See [Vector analysis](#2-cvss-vector-analysis-015-points) below |
| **Severity** | 30 | 30 | Severity multiplier × 30 (see table below; exponential spread) |
| **Fix available** | 5 | 5 | Binary: **5** if a fix version exists, else **0** |

**Formula for one CVE:**

```
score(CVE) = KEV_pts + EPSS_pts + Vector_pts + Severity_pts + Fix_pts
```

**Max score per CVE:** 30 + 20 + 15 + 30 + 5 = **100**

---

## 2. Severity component (0–30 points) — exponential spread

Severity uses a **wider spread** so Critical dominates and risk scales non-linearly (FAIR-style). Multiplier × **30**:

| Severity | Multiplier | Calculation | Points (max 30) |
|----------|------------|-------------|-----------------|
| CRITICAL | 1.0 | 1.0 × 30 | **30** |
| HIGH | 0.5 | 0.5 × 30 | **15** |
| MEDIUM | 0.15 | 0.15 × 30 | **4.5** |
| LOW | 0.03 | 0.03 × 30 | **0.9** |
| UNKNOWN | 0.01 | 0.01 × 30 | **0.3** |

Critical is ~33× Low so a single Critical is not eclipsed by many Lows.

---

## 3. CVSS Vector analysis (0–15 points)

The CVSS vector string is parsed into a **vector score** between 0 and 1.0, then multiplied by **15**. (Same as before: AV, AC, UI, S contributions; see repo for exact breakdown.)

**Vector points** = vector_score × **15**

---

## 4. Package risk: max + dampened sum (aggregation fix)

To prevent **"sum of lows"** from eclipsing a single Critical, package risk is **not** a raw sum of CVE scores. It uses the **max CVE score** plus a **dampened sum** of the rest:

1. Sort the package’s CVE scores **descending**.
2. **Base package risk** = `scores[0] + (sum of scores[1..n]) × DAMPENER`
3. **DAMPENER** = 0.1 (configurable in code, typically 0.05–0.2).

So one Critical (e.g. 55 pts) stays 55; ten Low/Med (e.g. avg 10) give 10 + (90 × 0.1) = **19**. Critical wins.

```
Base Package Risk = max(CVE scores) + sum(remaining CVE scores) × DAMPENER
```

---

## 5. KEV multiplier (ROI alignment)

Packages with **at least one KEV** CVE get an **adjusted risk** so that ROI % and ranking align (no more “#1 by rank but tiny ROI”):

- **Adjusted package risk** = Base package risk × **KEV_MULTIPLIER** if package has any KEV, else Base.
- **KEV_MULTIPLIER** = 2.5 (capped 2–3× in design).

**Total project risk** and **Risk reduction %** use **adjusted** package risks so that KEV-heavy packages show proportionally higher ROI.

```
Adjusted Package Risk = Base Package Risk × (hasKEV ? 2.5 : 1)
Total Project Risk    = Σ (Adjusted Package Risk)  for all packages with vulns
Risk Reduction %      = (Adjusted Package Risk / Total Project Risk) × 100
```

---

## 6. Ranking (priority order)

Packages are ordered by:

1. **KEV first** — Any package with at least one KEV CVE is ranked above packages with zero KEV.
2. **Then by adjusted package risk** — Higher score first.
3. **Then by max EPSS** — Higher first.
4. **Tie-break** — **Fewer CVEs = higher priority** (simpler fix).

---

## 7. Risk Dominator (UI)

For each top action, a one-line **“Why #1”** is shown from the **top CVE** (highest score):

- Format: **"1 &lt;Severity&gt; [RCE] (&lt;Attack Vector&gt;)"**
- Example: *"Driven by: 1 Critical RCE (Network)"*

This turns data into clear motivation (similar to enterprise “remediation summaries”).

---

## 8. Example

**Scenario A:** 1 Critical CVE, score 55 (e.g. KEV, high EPSS, Network).

- Base package risk = 55 (only one CVE).
- If KEV: adjusted = 55 × 2.5 = **137.5**. ROI = 137.5 / total_adjusted × 100.

**Scenario B:** 10 Low/Medium CVEs, avg score 10 each.

- Sorted: max = 10, rest sum = 90.
- Base package risk = 10 + 90 × 0.1 = **19**.
- No KEV: adjusted = 19. So this package ranks **below** the single Critical package and shows lower ROI %.

**CVE-2023-4863** (libwebp, KEV, EPSS 94.08%, Critical, fix available) — per-CVE example:

| Component | Calculation | Points |
|-----------|-------------|--------|
| KEV | 1 → 30 | 30 |
| EPSS | 0.9408 × 20 | 18.82 |
| Vector | e.g. AV:N, AC:L, UI:R → ~0.75 × 15 | 11.25 |
| Severity | CRITICAL 1.0 × 30 | 30 |
| Fix | 1 → 5 | 5 |
| **Total** | | **~95.07** |

If this is the only CVE for libwebp: base risk = 95.07, adjusted = 95.07 × 2.5 ≈ 237.7 (drives high ROI when total project risk is sum of adjusted risks).

---

## Constants (source code)

From `src/enrichment/metrics/remediation.ts`:

```ts
const WEIGHT_KEV = 30;
const WEIGHT_EPSS = 20;
const WEIGHT_CVSS_VECTOR = 15;
const WEIGHT_SEVERITY = 30;
const WEIGHT_FIX_AVAILABLE = 5;

const DAMPENER = 0.1;           // 0.05–0.2 for org tolerance
const KEV_MULTIPLIER = 2.5;    // 2–3× cap

const SEVERITY_SCORES = {
  CRITICAL: 1.0,
  HIGH: 0.5,
  MEDIUM: 0.15,
  LOW: 0.03,
  UNKNOWN: 0.01,
};
```

The same weights and formulas are used in the dashboard’s client-side `computeRemediation()` in `src/web/dashboard.ts`.
