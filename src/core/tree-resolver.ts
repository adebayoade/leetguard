import { LockfileData, PackageDependency } from '../types/index.js';

/**
 * Resolves the dependency tree from parsed lockfile data by building a Directed
 * Acyclic Graph (DAG) using Breadth-First Search (BFS).
 *
 * It accurately simulates npm's module resolution to trace dependencies through
 * both nested and hoisted physical paths, attaching the shortest logical path
 * (trace) from the project root to each package.
 *
 * @param lockfile - The parsed lockfile data containing dependencies.
 * @returns An array of all unique resolved dependencies with their vulnerability traces attached.
 */
export function resolveTree(lockfile: LockfileData): PackageDependency[] {
  const result: PackageDependency[] = [];
  const visited = new Set<string>();
  const queue: { name: string; trace: string[]; context: string }[] = [];

  const rootDeps = lockfile.rootDependencies || {};
  for (const depName of Object.keys(rootDeps)) {
    queue.push({ name: depName, trace: [depName], context: '' });
  }

  // Fallback for v1 lockfiles or empty root deps
  if (Object.keys(rootDeps).length === 0) {
    for (const [key, pkg] of lockfile.dependencies.entries()) {
      if (!key.includes('/node_modules/')) {
        queue.push({ name: pkg.name, trace: [pkg.name], context: '' });
      }
    }
  }

  while (queue.length > 0) {
    const { name, trace, context } = queue.shift()!;

    let resolvedPath = '';
    let currentContext = context;

    while (true) {
      const testPath = currentContext
        ? `${currentContext}/node_modules/${name}`
        : `node_modules/${name}`;
      if (lockfile.dependencies.has(testPath)) {
        resolvedPath = testPath;
        break;
      }
      if (!currentContext) break;

      const parts = currentContext.split('/node_modules/');
      parts.pop();
      currentContext = parts.join('/node_modules/');
    }

    if (!resolvedPath) continue;

    if (visited.has(resolvedPath)) continue;
    visited.add(resolvedPath);

    const pkg = lockfile.dependencies.get(resolvedPath)!;
    const pkgWithTrace = { ...pkg, trace };
    result.push(pkgWithTrace);

    if (pkg.dependencies) {
      for (const childName of Object.keys(pkg.dependencies)) {
        queue.push({
          name: childName,
          trace: [...trace, childName],
          context: resolvedPath,
        });
      }
    }
  }

  // Ensure no package is skipped if our traversal misses it
  for (const [path, pkg] of lockfile.dependencies.entries()) {
    if (!visited.has(path)) {
      result.push({ ...pkg, trace: [pkg.name] });
    }
  }

  return result;
}
