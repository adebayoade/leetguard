import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { LockfileData, PackageDependency } from '../types/index.js';

/**
 * Parses the package manager lockfile in the given directory.
 * Currently supports package-lock.json.
 *
 * @param dir - The project directory containing the lockfile.
 * @returns The parsed lockfile data, or null if no supported lockfile is found.
 */
export function parseLockfile(dir: string): LockfileData | null {
  const npmLockPath = join(dir, 'package-lock.json');

  if (existsSync(npmLockPath)) {
    return parseNpmLock(npmLockPath);
  }

  // Future support for yarn.lock and pnpm-lock.yaml goes here
  return null;
}

/**
 * Reads and parses an npm package-lock.json file.
 * Handles both v2 and v3 lockfile formats.
 *
 * @param filePath - The absolute path to the package-lock.json file.
 * @returns An object containing the root package info and its dependencies.
 */
function parseNpmLock(filePath: string): LockfileData {
  const content = readFileSync(filePath, 'utf-8');
  const json = JSON.parse(content);

  const dependencies = new Map<string, PackageDependency>();

  // Support npm v2 and v3 lockfiles
  const packages = json.packages || json.dependencies || {};

  for (const [key, pkg] of Object.entries<any>(packages)) {
    // In package-lock v2/v3, the root project is ""
    if (key === '') continue;

    // Extract real package name from paths like "node_modules/chalk"
    const name = key.replace(/^.*node_modules\//, '');

    dependencies.set(name, {
      name,
      version: pkg.version,
      resolved: pkg.resolved,
      integrity: pkg.integrity,
      dev: pkg.dev || false,
      dependencies: pkg.dependencies || pkg.requires || {},
    });
  }

  return {
    name: json.name,
    version: json.version,
    lockfileVersion: json.lockfileVersion,
    dependencies,
  };
}
