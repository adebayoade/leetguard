import { readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import { AntiPatternCategory, Finding } from '../../types/index.js';
import { getIsoControl } from '../iso-mapper.js';

// Babel's traverse export can be tricky in ESM
const traverse = typeof _traverse === 'function' ? _traverse : (_traverse as any).default;

const IGNORE_DIRS = ['node_modules', 'dist', 'build', '.git', '.next', '.nuxt', 'coverage'];
const ALLOWED_EXTS = ['.js', '.jsx', '.ts', '.tsx'];

/**
 * Recursively finds all source code files within a given directory,
 * ignoring explicitly excluded directories (like node_modules and .git).
 *
 * @param dir - The root directory to start the search.
 * @returns An array of absolute file paths to valid source files.
 */
export function findSourceFiles(dir: string): string[] {
  let results: string[] = [];
  try {
    const list = readdirSync(dir);
    for (const file of list) {
      if (IGNORE_DIRS.includes(file)) continue;

      const fullPath = join(dir, file);
      const stat = statSync(fullPath);

      if (stat && stat.isDirectory()) {
        results = results.concat(findSourceFiles(fullPath));
      } else {
        if (ALLOWED_EXTS.some((ext) => file.endsWith(ext))) {
          results.push(fullPath);
        }
      }
    }
  } catch (error) {
    console.error(`Failed to read directory: ${dir}`, error);
  }
  return results;
}

/**
 * Scans the source code of a project using an Abstract Syntax Tree (AST) parser
 * to identify known security anti-patterns (e.g. eval, console.log data exposure).
 *
 * @param dir - The project directory to scan.
 * @returns An array of security findings representing the detected anti-patterns.
 */
export function scanSourceCode(dir: string): Finding[] {
  const files = findSourceFiles(dir);
  const findings: Finding[] = [];

  for (const file of files) {
    try {
      const code = readFileSync(file, 'utf-8');
      const ast = parse(code, {
        sourceType: 'module',
        plugins: ['typescript', 'jsx', 'decorators-legacy', 'importAssertions'],
      });

      traverse(ast, {
        CallExpression(path: any) {
          const callee = path.node.callee;

          // 1. eval() usage
          if (callee.type === 'Identifier' && callee.name === 'eval') {
            findings.push(createFinding('eval() usage', file, path.node.loc?.start.line));
          }

          // 5. sensitive data in console.log
          if (
            callee.type === 'MemberExpression' &&
            callee.object.name === 'console' &&
            callee.property.name === 'log'
          ) {
            findings.push(
              createFinding('sensitive data in console.log', file, path.node.loc?.start.line),
            );
          }

          // 6. insecure AsyncStorage
          if (
            callee.type === 'MemberExpression' &&
            callee.object.name === 'AsyncStorage' &&
            callee.property.name === 'setItem'
          ) {
            findings.push(createFinding('insecure AsyncStorage', file, path.node.loc?.start.line));
          }
        },
        NewExpression(path: any) {
          // 2. new Function()
          const callee = path.node.callee;
          if (callee.type === 'Identifier' && callee.name === 'Function') {
            findings.push(createFinding('new Function()', file, path.node.loc?.start.line));
          }
        },
        StringLiteral(path: any) {
          const value = path.node.value;

          // 4. hardcoded secrets and API keys
          if (/(sk_live_[0-9a-zA-Z]{24})|(AKIA[0-9A-Z]{16})/.test(value)) {
            findings.push(
              createFinding('hardcoded secrets and API keys', file, path.node.loc?.start.line),
            );
          }

          // 7. missing HTTPS in hardcoded API URLs
          if (
            value.startsWith('http://') &&
            !value.includes('localhost') &&
            !value.includes('127.0.0.1')
          ) {
            findings.push(
              createFinding('missing HTTPS in hardcoded API URLs', file, path.node.loc?.start.line),
            );
          }
        },
        JSXOpeningElement(path: any) {
          // 8. unvalidated WebView URIs
          const name = path.node.name;
          if (name.type === 'JSXIdentifier' && name.name === 'WebView') {
            findings.push(
              createFinding('unvalidated WebView URIs', file, path.node.loc?.start.line),
            );
          }
        },
      });
    } catch (error) {
      // Ignore parse errors for individual files
    }
  }

  return findings;
}

/**
 * Creates a standardized Finding object for a detected anti-pattern.
 *
 * @param patternName - The name of the detected pattern.
 * @param file - The file path where the pattern was found.
 * @param line - The line number where the pattern was found.
 * @returns A structured Finding object.
 */
function createFinding(patternName: string, file: string, line: number | undefined): Finding {
  const lineSuffix = line ? `:${line}` : '';
  const category = determineCategory(patternName);

  return {
    category,
    patternName,
    severity: 'High',
    description: `Found in ${file}${lineSuffix}`,
    isoControl: getIsoControl(patternName),
  };
}

/**
 * Determines the broader category for a specific anti-pattern.
 *
 * @param pattern - The specific pattern name.
 * @returns The overarching anti-pattern category.
 */
function determineCategory(pattern: string): AntiPatternCategory {
  if (['eval() usage', 'new Function()'].includes(pattern)) return 'Injection & Dynamic Execution';
  if (
    [
      'hardcoded secrets and API keys',
      'sensitive data in console.log',
      'insecure AsyncStorage',
    ].includes(pattern)
  )
    return 'Data Exposure';
  if (pattern === 'missing HTTPS in hardcoded API URLs') return 'Transport & Communication';
  return 'React Native Mobile Risks';
}
