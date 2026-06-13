import { LockfileData, PackageDependency } from '../types/index.js';

/**
 * Resolves the dependency tree from parsed lockfile data into a flat list.
 *
 * @param lockfile - The parsed lockfile data containing dependencies.
 * @returns A flat array of all unique resolved dependencies.
 */
export function resolveTree(lockfile: LockfileData): PackageDependency[] {
  // For now, we simply return a flat list of all unique resolved dependencies.
  // In a more complex scenario, we would build an actual graph.
  const flatList: PackageDependency[] = [];

  for (const [_name, pkg] of lockfile.dependencies.entries()) {
    flatList.push(pkg);
  }

  return flatList;
}
