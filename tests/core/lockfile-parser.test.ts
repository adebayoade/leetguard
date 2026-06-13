import { describe, it, expect } from 'vitest';
import { parseLockfile } from '../../src/core/lockfile-parser.js';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

describe('LockfileParser', () => {
  it('should parse an npm package-lock.json correctly', () => {
    // Point to our mock fixture directory
    const fixtureDir = join(__dirname, '../fixtures');

    const lockfile = parseLockfile(fixtureDir);

    // Validate core properties
    expect(lockfile).not.toBeNull();
    expect(lockfile?.name).toBe('mock-project');
    expect(lockfile?.version).toBe('1.0.0');
    expect(lockfile?.lockfileVersion).toBe(2);

    // Validate dependencies were extracted properly
    expect(lockfile?.dependencies.size).toBe(2);
    expect(lockfile?.dependencies.has('chalk')).toBe(true);
    expect(lockfile?.dependencies.has('commander')).toBe(true);

    const chalkPkg = lockfile?.dependencies.get('chalk');
    expect(chalkPkg?.version).toBe('4.1.2');
    expect(chalkPkg?.name).toBe('chalk');
  });

  it('should return null if no lockfile is found', () => {
    const emptyDir = join(__dirname, '../empty-dir');
    const lockfile = parseLockfile(emptyDir);
    expect(lockfile).toBeNull();
  });
});
