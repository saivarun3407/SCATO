#!/usr/bin/env node

// ─── SCATO CLI (v3) ───
// Software Composition Analysis Tool — Simple, Fast, Comprehensive

import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import { resolve } from "path";
import { scan } from "./scanner.js";
import { printReport } from "./core/output/terminal.js";
import { formatJsonReport } from "./core/output/json.js";
import type { Ecosystem, VulnerabilitySource } from "./types.js";

const VERSION = "3.0.0";

const program = new Command();

program
  .name("scato")
  .description(
    "Software Composition Analysis Tool\n" +
    "Find vulnerabilities, generate SBOMs, enforce security policies"
  )
  .version(VERSION);

// ─── Main scan command ───
program
  .command("scan", { isDefault: true })
  .description("Scan a project for vulnerabilities")
  .argument("[directory]", "Target directory to scan", ".")
  .option("-j, --json", "Output results as JSON")
  .option("-s, --sbom <path>", "Generate SBOM at specified path")
  .option("--sbom-format <format>", "SBOM format: cyclonedx (default) or spdx", "cyclonedx")
  .option("--sarif <path>", "Generate SARIF report for code scanning")
  .option("-e, --ecosystem <ecosystems...>", "Limit to specific ecosystems")
  .option("--skip-licenses", "Skip license detection (faster scan)")
  .option("--skip-dev", "Skip dev/test dependencies")
  .option("--fail-on <severity>", "Exit with code 1 at or above severity", "high")
  .option("--sources <sources...>", "Vulnerability sources (osv,nvd,ghsa,kev,epss)")
  .option("--nvd-api-key <key>", "NVD API key for enhanced data")
  .option("--github-token <token>", "GitHub token for GHSA and PR integration")
  .option("--policy <path>", "Path to policy JSON file")
  .option("--ci", "Force CI mode (auto-detected normally)")
  .option("--pr-comment", "Post scan results as PR comment (GitHub)")
  .option("--check-run", "Create GitHub check run with results")
  .option("--offline", "Use cached data only (no network requests)")
  .action(async (directory: string, options: any) => {
    const target = resolve(directory);

    let isCI = options.ci;
    if (!isCI) {
      try {
        const { detectCI } = await import("./integrations/ci/detect.js");
        isCI = detectCI().isCI;
      } catch { isCI = false; }
    }

    if (!options.json && !isCI) {
      console.log();
      console.log(
        chalk.cyan.bold("  SCATO") +
        chalk.gray(` v${VERSION}`) +
        chalk.gray(" — Software Composition Analysis Tool")
      );
      console.log();
    }

    const spinner = !options.json && !isCI
      ? ora({ text: "Discovering dependencies...", indent: 2 }).start()
      : null;

    try {
      const ecosystems = options.ecosystem as Ecosystem[] | undefined;
      const sources = options.sources as VulnerabilitySource[] | undefined;

      if (spinner) spinner.text = "Scanning for vulnerabilities...";

      const report = await scan({
        target,
        outputJson: options.json,
        sbomOutput: options.sbom,
        sbomFormat: options.sbomFormat,
        sarifOutput: options.sarif,
        skipLicenses: options.skipLicenses,
        skipDev: options.skipDev,
        ecosystems,
        sources,
        nvdApiKey: options.nvdApiKey || process.env.NVD_API_KEY,
        githubToken: options.githubToken || process.env.GITHUB_TOKEN,
        policyFile: options.policy,
        ciMode: isCI,
        prComment: options.prComment,
        checkRun: options.checkRun,
        offlineMode: options.offline,
      });

      if (spinner) spinner.stop();

      if (options.json) {
        console.log(formatJsonReport(report));
      } else {
        await printReport(report);
      }

      // Exit code based on policy or severity
      if (report.policyResult && !report.policyResult.passed) {
        process.exit(1);
      }

      const failSeverity = (options.failOn || "high").toUpperCase();
      const severityOrder = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
      const failIndex = severityOrder.indexOf(failSeverity);

      if (failIndex >= 0) {
        const hasFailingSeverity = severityOrder
          .slice(failIndex)
          .some((sev) => report.severityCounts[sev as keyof typeof report.severityCounts] > 0);

        if (hasFailingSeverity) {
          process.exit(1);
        }
      }
    } catch (err) {
      if (spinner) spinner.fail("Scan failed");
      console.error(chalk.red(`  Error: ${err}`));
      process.exit(2);
    }
  });

// ─── SBOM command ───
program
  .command("sbom")
  .description("Generate a Software Bill of Materials")
  .argument("[directory]", "Target directory", ".")
  .option("-o, --output <path>", "Output file path", "sbom.json")
  .option("-f, --format <format>", "Format: cyclonedx (default) or spdx", "cyclonedx")
  .action(async (directory: string, options: any) => {
    const target = resolve(directory);
    const spinner = ora({ text: "Generating SBOM...", indent: 2 }).start();

    try {
      const report = await scan({
        target,
        sbomOutput: options.output,
        sbomFormat: options.format,
        skipLicenses: false,
      });

      spinner.succeed(`SBOM generated: ${options.output}`);
      console.log(chalk.gray(`  ${report.totalDependencies} dependencies from ${report.ecosystems.join(", ")}`));
    } catch (err) {
      spinner.fail("SBOM generation failed");
      console.error(chalk.red(`  Error: ${err}`));
      process.exit(2);
    }
  });

// ─── Tree command ───
program
  .command("tree")
  .description("Scan and print dependency tree")
  .argument("[directory]", "Target directory to scan", ".")
  .option("-j, --json", "Output tree as JSON")
  .option("--skip-dev", "Skip dev dependencies")
  .action(async (directory: string, options: any) => {
    const target = resolve(directory);
    const spinner = ora({ text: "Scanning dependencies...", indent: 2 }).start();

    try {
      const report = await scan({
        target,
        skipDev: options.skipDev ?? false,
        skipLicenses: true,
      });
      spinner.succeed("Scan complete");

      if (report.dependencyTrees && report.dependencyTrees.length > 0) {
        if (options.json) {
          console.log(JSON.stringify(report.dependencyTrees, null, 2));
        } else {
          const { printDependencyTree } = await import("./core/tree/terminal.js");
          printDependencyTree(report.dependencyTrees, report.results);
        }
      } else {
        console.log(chalk.gray("  No dependency tree (flat list only)."));
        console.log(chalk.gray(`  ${report.totalDependencies} dependencies in ${report.ecosystems.join(", ")}.`));
      }
    } catch (err) {
      spinner.fail("Scan failed");
      console.error(chalk.red(`  Error: ${err}`));
      process.exit(2);
    }
  });

// ─── History command ───
program
  .command("history")
  .description("View scan history")
  .option("-t, --target <path>", "Filter by target directory")
  .option("-n, --limit <number>", "Number of recent scans", "10")
  .action(async (options: any) => {
    try {
      const { getDatabase, closeDatabase } = await import("./storage/database.js");
      const db = getDatabase();
      const scans = db.getRecentScans(
        options.target ? resolve(options.target) : undefined,
        parseInt(options.limit, 10)
      );

      if (scans.length === 0) {
        console.log(chalk.gray("  No scan history found."));
        closeDatabase();
        return;
      }

      console.log();
      console.log(chalk.cyan.bold("  Scan History"));
      console.log(chalk.gray("  ─────────────────────────────────────────────"));

      for (const s of scans) {
        const date = new Date(s.timestamp).toLocaleString();
        const riskColor = s.riskScore >= 60 ? chalk.red : s.riskScore >= 30 ? chalk.yellow : chalk.green;

        console.log(
          chalk.gray(`  ${date}`) + "  " +
          chalk.white(s.target.split("/").pop()) + "  " +
          chalk.gray(`${s.totalDeps} deps`) + "  " +
          (s.totalVulns > 0 ? chalk.red(`${s.totalVulns} vulns`) : chalk.green("0 vulns")) + "  " +
          riskColor(`risk: ${s.riskScore}`)
        );
      }
      console.log();
      closeDatabase();
    } catch (err) {
      console.error(chalk.red(`Error: ${err}`));
    }
  });

// ─── Trend command ───
program
  .command("trend")
  .description("View vulnerability trend for a project")
  .argument("<directory>", "Target directory")
  .option("-d, --days <number>", "Number of days to show", "30")
  .action(async (directory: string, options: any) => {
    try {
      const { getDatabase, closeDatabase } = await import("./storage/database.js");
      const db = getDatabase();
      const target = resolve(directory);
      const trend = db.getTrend(target, parseInt(options.days, 10));

      if (trend.length === 0) {
        console.log(chalk.gray("  No trend data available. Run multiple scans to build history."));
        closeDatabase();
        return;
      }

      console.log();
      console.log(chalk.cyan.bold("  Vulnerability Trend"));
      console.log(chalk.gray("  ─────────────────────────────────────────────"));

      for (const point of trend) {
        const critBar = chalk.red("█".repeat(point.criticalCount));
        const highBar = chalk.yellow("█".repeat(point.highCount));
        const restBar = chalk.blue("█".repeat(Math.max(0, point.totalVulns - point.criticalCount - point.highCount)));

        console.log(
          chalk.gray(`  ${point.date}  `) +
          critBar + highBar + restBar +
          chalk.gray(` ${point.totalVulns} (risk: ${point.riskScore})`)
        );
      }
      console.log();
      closeDatabase();
    } catch (err) {
      console.error(chalk.red(`Error: ${err}`));
    }
  });

// ─── Serve command (web dashboard) ───
program
  .command("serve")
  .description("Start the web dashboard and API server")
  .option("-p, --port <number>", "Port to listen on", "3001")
  .option("--open", "Auto-open the dashboard in your browser")
  .action(async (options: any) => {
    const port = parseInt(options.port, 10);

    console.log();
    console.log(
      chalk.cyan.bold("  SCATO") +
      chalk.gray(` v${VERSION}`) +
      chalk.gray(" — Web Dashboard")
    );
    console.log();

    try {
      const { startServer } = await import("./server.js");
      await startServer({ port, open: options.open });
    } catch (err) {
      console.error(chalk.red(`  Error starting server: ${err}`));
      process.exit(2);
    }
  });

// ─── Policy init command ───
program
  .command("policy-init")
  .description("Generate a default policy file")
  .argument("[path]", "Output path", ".scato-policy.json")
  .action(async (path: string) => {
    try {
      const { DEFAULT_POLICY } = await import("./integrations/policy/engine.js");
      const { writeFile } = await import("fs/promises");

      const policyDoc = {
        $schema: "https://scato.dev/schemas/policy-v1.json",
        description: "SCATO security policy",
        rules: DEFAULT_POLICY,
      };

      await writeFile(resolve(path), JSON.stringify(policyDoc, null, 2));
      console.log(chalk.green(`  Policy file created: ${path}`));
    } catch (err) {
      console.error(chalk.red(`Error: ${err}`));
    }
  });

program.parse();
