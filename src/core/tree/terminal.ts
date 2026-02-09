// ─── Dependency tree terminal output ───

import chalk from "chalk";
import type { DependencyTree, DependencyNode } from "../../types.js";

const BRANCH = "├── ";
const LAST = "└── ";
const PIPE = "│   ";
const SPACE = "    ";

function formatNode(node: DependencyNode, vulnCount: number): string {
  const dep = node.dependency;
  const label = `${dep.name}@${dep.version}`;
  const vulnStr = vulnCount > 0 ? chalk.red(` (${vulnCount} vuln${vulnCount === 1 ? "" : "s"})`) : "";
  return label + vulnStr;
}

function printNode(
  node: DependencyNode,
  prefix: string,
  isLast: boolean,
  vulnMap: Map<string, number>
): void {
  const key = `${node.dependency.ecosystem}:${node.dependency.name}@${node.dependency.version}`;
  const vulnCount = vulnMap.get(key) ?? 0;
  const connector = isLast ? LAST : BRANCH;
  console.log(prefix + connector + formatNode(node, vulnCount));

  const childCount = node.children.length;
  const newPrefix = prefix + (isLast ? SPACE : PIPE);
  node.children.forEach((child, i) => {
    printNode(child, newPrefix, i === childCount - 1, vulnMap);
  });
}

function buildVulnMap(results: { dependency: { ecosystem: string; name: string; version: string }; vulnerabilities: unknown[] }[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const r of results) {
    const key = `${r.dependency.ecosystem}:${r.dependency.name}@${r.dependency.version}`;
    m.set(key, r.vulnerabilities.length);
  }
  return m;
}

/**
 * Print dependency trees to the terminal (indented tree view).
 */
export function printDependencyTree(trees: DependencyTree[], results?: { dependency: { ecosystem: string; name: string; version: string }; vulnerabilities: unknown[] }[]): void {
  const vulnMap = results ? buildVulnMap(results) : new Map<string, number>();

  for (const tree of trees) {
    console.log();
    console.log(chalk.cyan.bold(`  ${tree.ecosystem}`) + chalk.gray(` (${tree.directCount} direct, ${tree.transitiveCount} transitive, depth ${tree.maxDepth})`));
    console.log(chalk.gray("  " + "─".repeat(50)));

    if (tree.nodes.length === 0) {
      console.log(chalk.gray("  (no dependencies)"));
      continue;
    }

    tree.nodes.forEach((node, i) => {
      printNode(node, "  ", i === tree.nodes.length - 1, vulnMap);
    });
    console.log();
  }
}
