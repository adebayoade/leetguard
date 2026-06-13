import { describe, it, expect } from 'vitest';
import { scanSourceCode } from '../../src/intelligence/scanner/ast-scanner.js';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

describe('AST Scanner', () => {
  it('should detect anti-patterns in source code', () => {
    const fixtureDir = join(__dirname, '../fixtures/src');
    const findings = scanSourceCode(fixtureDir);

    // We expect 5 findings based on dummy.js
    // 1. eval()
    // 2. new Function()
    // 3. console.log()
    // 4. hardcoded secret (AKIA...)
    // 5. http:// URL

    expect(findings.length).toBe(5);

    const patternNames = findings.map((f) => f.patternName);

    expect(patternNames).toContain('eval() usage');
    expect(patternNames).toContain('new Function()');
    expect(patternNames).toContain('sensitive data in console.log');
    expect(patternNames).toContain('hardcoded secrets and API keys');
    expect(patternNames).toContain('missing HTTPS in hardcoded API URLs');
  });
});
