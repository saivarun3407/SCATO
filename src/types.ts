// ─── Core Types for SCATO ───
// Software Composition Analysis Tool - Production Grade

// ═══════════════════════════════════════════
// Ecosystem & Dependency Types
// ═══════════════════════════════════════════

export type Ecosystem = "npm" | "pip" | "go" | "maven" | "cargo" | "nuget" | "gem" | "composer";

export interface Dependency {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  isDirect: boolean;
  parent?: string;
  license?: string;
  purl?: string; // Package URL (pkg:npm/express@4.18.2)
  integrity?: string; // hash for verification
  scope?: "runtime" | "dev" | "optional" | "peer";
}

export interface DependencyNode {
  dependency: Dependency;
  children: DependencyNode[];
  depth: number;
}

export interface DependencyTree {
  root: string;
  ecosystem: Ecosystem;
  nodes: DependencyNode[];
  totalCount: number;
  directCount: number;
  transitiveCount: number;
  maxDepth: number;
}

// ═══════════════════════════════════════════
// Vulnerability Types
// ═══════════════════════════════════════════

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export type VulnerabilitySource = "osv" | "nvd" | "ghsa" | "kev" | "epss";

export interface Vulnerability {
  id: string;
  aliases: string[];
  summary: string;
  details: string;
  severity: Severity;
  score?: number; // CVSS score
  cvssVector?: string;
  affected_versions: string;
  fixed_version?: string;
  references: string[];
  published: string;
  modified?: string;
  source: VulnerabilitySource;
  // KEV-specific
  isKnownExploited?: boolean;
  kevDateAdded?: string;
  kevDueDate?: string;
  // EPSS-specific
  epssScore?: number; // 0.0-1.0 probability
  epssPercentile?: number;
  // CWE
  cwes?: string[];
}

// ═══════════════════════════════════════════
// Scan Types
// ═══════════════════════════════════════════

export interface ScanResult {
  dependency: Dependency;
  vulnerabilities: Vulnerability[];
}

export interface ScanReport {
  tool: string;
  version: string;
  timestamp: string;
  target: string;
  ecosystems: Ecosystem[];
  totalDependencies: number;
  totalVulnerabilities: number;
  severityCounts: Record<Severity, number>;
  results: ScanResult[];
  sbomPath?: string;
  // Extended metrics
  metrics?: ScanMetrics;
  // Policy evaluation
  policyResult?: PolicyResult;
  // Dependency trees
  dependencyTrees?: DependencyTree[];
  // Scan metadata
  scanDurationMs?: number;
  scanId?: string;
  // Data source timestamps
  dataSourceTimestamps?: Record<VulnerabilitySource, string>;
}

export interface ScanMetrics {
  // Risk scoring
  riskScore: number; // 0-100 composite score
  riskLevel: "critical" | "high" | "medium" | "low" | "none";

  // Vulnerability metrics
  criticalWithFix: number;
  highWithFix: number;
  medianVulnAge: number; // days
  oldestUnfixedVuln?: { id: string; age: number; severity: Severity };

  // KEV metrics
  kevCount: number;
  kevWithFix: number;

  // EPSS metrics
  avgEpssScore: number;
  maxEpssScore: number;
  highEpssCount: number; // EPSS > 0.5

  // License metrics
  copyleftCount: number;
  unknownLicenseCount: number;
  uniqueLicenses: number;

  // Dependency metrics
  directDependencies: number;
  transitiveDependencies: number;
  maxDepth: number;
  outdatedCount: number;

  // Trend data (if historical data available)
  trend?: {
    vulnCountDelta: number;
    riskScoreDelta: number;
    newVulnsSinceLastScan: number;
    fixedSinceLastScan: number;
  };
}

// ═══════════════════════════════════════════
// Policy Types
// ═══════════════════════════════════════════

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  severity: "error" | "warning" | "info";
  condition: PolicyCondition;
}

export type PolicyCondition =
  | { type: "max_severity"; value: Severity }
  | { type: "max_cvss"; value: number }
  | { type: "no_kev" }
  | { type: "max_epss"; value: number }
  | { type: "no_copyleft" }
  | { type: "no_unknown_license" }
  | { type: "max_vuln_age"; days: number }
  | { type: "custom"; expression: string };

export interface PolicyResult {
  passed: boolean;
  violations: PolicyViolation[];
  warnings: PolicyViolation[];
}

export interface PolicyViolation {
  ruleId: string;
  ruleName: string;
  message: string;
  severity: "error" | "warning" | "info";
  dependency?: string;
  vulnerability?: string;
}

// ═══════════════════════════════════════════
// License Types
// ═══════════════════════════════════════════

export interface LicenseInfo {
  name: string;
  spdxId: string;
  isOsiApproved: boolean;
  isCopyleft: boolean;
  risk: "low" | "medium" | "high";
}

// ═══════════════════════════════════════════
// Parser Types
// ═══════════════════════════════════════════

export interface ParserResult {
  ecosystem: Ecosystem;
  file: string;
  dependencies: Dependency[];
  dependencyTree?: DependencyTree;
}

// ═══════════════════════════════════════════
// Configuration Types
// ═══════════════════════════════════════════

export interface ScatoConfig {
  // Scan options
  target: string;
  ecosystems?: Ecosystem[];
  skipLicenses?: boolean;
  skipDev?: boolean;

  // Output options
  outputJson?: boolean;
  sbomOutput?: string;
  sbomFormat?: "cyclonedx" | "spdx";
  sarifOutput?: string;

  // Data sources
  sources?: VulnerabilitySource[];
  nvdApiKey?: string;
  githubToken?: string;

  // Policy
  policyFile?: string;
  failOn?: Severity;

  // Cache
  cacheDir?: string;
  offlineMode?: boolean;

  // CI/CD
  ciMode?: boolean;
  prComment?: boolean;
  checkRun?: boolean;

  // Performance
  concurrency?: number;
  timeout?: number;
}

// ═══════════════════════════════════════════
// Storage Types (scan history, cache)
// ═══════════════════════════════════════════

export interface ScanRecord {
  id: string;
  target: string;
  timestamp: string;
  durationMs: number;
  totalDeps: number;
  totalVulns: number;
  riskScore: number;
  severityCounts: string; // JSON
  report: string; // JSON compressed
}

export interface VulnCacheEntry {
  id: string;
  source: VulnerabilitySource;
  data: string; // JSON
  fetchedAt: string;
  expiresAt: string;
}

// ═══════════════════════════════════════════
// OSV API types
// ═══════════════════════════════════════════

export interface OSVQuery {
  package: {
    name: string;
    ecosystem: string;
  };
  version: string;
}

export interface OSVBatchQuery {
  queries: OSVQuery[];
}

export interface OSVVulnerability {
  id: string;
  aliases: string[];
  summary: string;
  details: string;
  severity: Array<{
    type: string;
    score: string;
  }>;
  affected: Array<{
    package: {
      name: string;
      ecosystem: string;
    };
    ranges: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
    versions: string[];
  }>;
  references: Array<{
    type: string;
    url: string;
  }>;
  published: string;
  modified: string;
  database_specific?: Record<string, unknown>;
}

export interface OSVBatchResponse {
  results: Array<{
    vulns?: OSVVulnerability[];
  }>;
}

// ═══════════════════════════════════════════
// CycloneDX SBOM types
// ═══════════════════════════════════════════

export interface CycloneDXBom {
  bomFormat: "CycloneDX";
  specVersion: "1.5";
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: {
      components: Array<{
        type: string;
        name: string;
        version: string;
      }>;
    };
    component?: {
      type: string;
      name: string;
    };
  };
  components: CycloneDXComponent[];
  dependencies?: CycloneDXDependency[];
  vulnerabilities?: CycloneDXVulnerability[];
}

export interface CycloneDXComponent {
  type: "library";
  name: string;
  version: string;
  purl: string;
  "bom-ref": string;
  licenses?: Array<{
    license: {
      id?: string;
      name?: string;
    };
  }>;
  properties?: Array<{
    name: string;
    value: string;
  }>;
  scope?: string;
}

export interface CycloneDXDependency {
  ref: string;
  dependsOn?: string[];
}

export interface CycloneDXVulnerability {
  id: string;
  source: {
    name: string;
    url: string;
  };
  ratings: Array<{
    severity: string;
    score?: number;
    method?: string;
    vector?: string;
  }>;
  cwes?: number[];
  description: string;
  affects: Array<{
    ref: string;
  }>;
  properties?: Array<{
    name: string;
    value: string;
  }>;
}

// ═══════════════════════════════════════════
// SARIF Output Types
// ═══════════════════════════════════════════

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  helpUri?: string;
  defaultConfiguration: {
    level: "error" | "warning" | "note";
  };
}

export interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations?: Array<{
    physicalLocation: {
      artifactLocation: {
        uri: string;
      };
    };
  }>;
}

// ═══════════════════════════════════════════
// GitHub Integration Types
// ═══════════════════════════════════════════

export interface GitHubContext {
  owner: string;
  repo: string;
  sha: string;
  prNumber?: number;
  token: string;
  apiUrl?: string; // for GHE
}

export interface CheckRunResult {
  conclusion: "success" | "failure" | "neutral";
  title: string;
  summary: string;
  annotations: Array<{
    path: string;
    start_line: number;
    end_line: number;
    annotation_level: "notice" | "warning" | "failure";
    message: string;
    title: string;
  }>;
}

// ═══════════════════════════════════════════
// CI/CD Integration Types
// ═══════════════════════════════════════════

export type CIPlatform = "github-actions" | "gitlab-ci" | "jenkins" | "azure-devops" | "circleci" | "generic";

export interface CIEnvironment {
  platform: CIPlatform;
  buildId?: string;
  branch?: string;
  commitSha?: string;
  prNumber?: number;
  repository?: string;
  isCI: boolean;
}
