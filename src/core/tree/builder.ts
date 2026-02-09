// ─── Dependency tree builder ───
// Builds hierarchical DependencyTree from flat ScanResult[] using parent references.

import type {
  ScanResult,
  DependencyTree,
  DependencyNode,
  Dependency,
  Ecosystem,
} from "../../types.js";

function depKey(d: Dependency): string {
  return `${d.ecosystem}:${d.name}@${d.version}`;
}

/**
 * Build dependency trees per ecosystem from flat scan results.
 * Uses dependency.parent to attach children. Ecosystems without parent info get flat roots.
 */
export function buildDependencyTrees(results: ScanResult[]): DependencyTree[] {
  const byEcosystem = new Map<Ecosystem, ScanResult[]>();
  for (const r of results) {
    const eco = r.dependency.ecosystem;
    if (!byEcosystem.has(eco)) byEcosystem.set(eco, []);
    byEcosystem.get(eco)!.push(r);
  }

  const trees: DependencyTree[] = [];
  for (const [ecosystem, list] of byEcosystem) {
    const direct = list.filter((r) => r.dependency.isDirect);
    const transitive = list.filter((r) => !r.dependency.isDirect);

    // parent name -> children (ScanResult with that parent)
    const parentToChildren = new Map<string, ScanResult[]>();
    for (const r of transitive) {
      const parent = r.dependency.parent ?? "";
      if (!parentToChildren.has(parent)) parentToChildren.set(parent, []);
      parentToChildren.get(parent)!.push(r);
    }

    const seen = new Set<string>();
    let maxDepth = 0;

    function buildNode(result: ScanResult, depth: number): DependencyNode {
      const key = depKey(result.dependency);
      if (seen.has(key)) {
        return { dependency: result.dependency, children: [], depth };
      }
      seen.add(key);
      if (depth > maxDepth) maxDepth = depth;

      const childrenResults = parentToChildren.get(result.dependency.name) ?? [];
      const children = childrenResults.map((c) => buildNode(c, depth + 1));

      return {
        dependency: result.dependency,
        children,
        depth,
      };
    }

    const rootNodes: DependencyNode[] = direct.map((r) => buildNode(r, 0));

    trees.push({
      root: "project",
      ecosystem,
      nodes: rootNodes,
      totalCount: list.length,
      directCount: direct.length,
      transitiveCount: transitive.length,
      maxDepth,
    });
  }

  return trees;
}
