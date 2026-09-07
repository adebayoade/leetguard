import { describe, it, expect } from 'vitest';
import { scanSourceCode } from '../../src/intelligence/scanner/ast-scanner.js';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

describe('AST Scanner', () => {
  const fixtureDir = join(__dirname, '../fixtures/src');
  const findings = scanSourceCode(fixtureDir);
  const patternNames = findings.map((f) => f.summary);

  it('should detect all seven anti-pattern categories in source code', () => {
    // dummy.js contains exactly one instance of each of the seven target
    // patterns, plus two safe loopback URLs that must NOT be flagged.
    expect(findings.length).toBe(7);
  });

  it('should detect eval() usage', () => {
    expect(patternNames).toContain('eval() usage');
  });

  it('should detect new Function() instantiation', () => {
    expect(patternNames).toContain('new Function()');
  });

  it('should detect sensitive data logged via console.log', () => {
    expect(patternNames).toContain('sensitive data in console.log');
  });

  it('should detect hardcoded secrets and API keys', () => {
    expect(patternNames).toContain('hardcoded secrets and API keys');
  });

  it('should detect hardcoded http:// API URLs', () => {
    expect(patternNames).toContain('missing HTTPS in hardcoded API URLs');
  });

  it('should detect insecure AsyncStorage usage', () => {
    expect(patternNames).toContain('insecure AsyncStorage');
  });

  it('should detect unvalidated WebView URIs', () => {
    expect(patternNames).toContain('unvalidated WebView URIs');
  });

  it('should not flag http://localhost or http://127.0.0.1 as insecure URLs', () => {
    const insecureUrlFindings = findings.filter(
      (f) => f.summary === 'missing HTTPS in hardcoded API URLs',
    );

    // Only the single genuine insecure URL in dummy.js should be flagged;
    // the loopback addresses in safeCode() must be excluded.
    expect(insecureUrlFindings.length).toBe(1);
    expect(insecureUrlFindings[0].details).toContain('dummy.js');
  });
});
