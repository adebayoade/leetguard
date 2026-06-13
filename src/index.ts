#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { readFileSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

import { parseLockfile } from './core/lockfile-parser.js';
import { resolveTree } from './core/tree-resolver.js';
import { generateTextReport } from './reporting/formats/text.js';
import { lookupCveBatch } from './intelligence/cve/osv-client.js';
import { checkAbandonedPackages } from './intelligence/abandonment/npm-registry.js';
import { scanSourceCode } from './intelligence/scanner/ast-scanner.js';
import { select } from '@inquirer/prompts';

// Workaround for __dirname in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const program = new Command();

// Read package.json to get the version
const packageJsonPath = join(__dirname, '../package.json');
const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));

program
  .name('leetguard')
  .description('LeetGuard - Security Anti-Pattern Scanner for Node.js projects')
  .version(pkg.version);

program
  .command('scan')
  .description('Scan a project directory for security anti-patterns')
  .argument('[dir]', 'Project directory to scan', '.')
  .option('-f, --format <format>', 'Output format (json, html, text, audit)')
  .action(async (dir, options) => {
    let format = options.format;

    if (!format) {
      format = await select({
        message: 'Select output format:',
        choices: [
          { name: 'Text (Human readable in terminal)', value: 'text' },
          { name: 'JSON (For CI/CD integration)', value: 'json' },
          { name: 'HTML (Browser report)', value: 'html' },
          { name: 'Audit (Compliance ready)', value: 'audit' },
        ],
      });
    }

    console.log(chalk.blue(`[LeetGuard] Scanning directory: ${dir}...`));

    // Layer 2: Core Engine
    const lockfile = parseLockfile(dir);

    if (!lockfile) {
      console.error(chalk.red('Error: Could not find or parse package-lock.json.'));
      process.exit(1);
    }

    const dependencies = resolveTree(lockfile);

    // Layer 3: Intelligence
    const vulnerabilities = await lookupCveBatch(dependencies);

    let directDeps: string[] = [];
    try {
      const pkgJson = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf-8'));
      directDeps = Object.keys(pkgJson.dependencies || {}).concat(
        Object.keys(pkgJson.devDependencies || {}),
      );
    } catch (e) {
      console.warn(
        chalk.yellow(`Could not read package.json in ${dir}. Skipping abandonment checks.`),
      );
    }
    const abandonedPackages = await checkAbandonedPackages(directDeps);

    console.log(chalk.blue(`[LeetGuard] Scanning source code for anti-patterns...`));
    const codeAntiPatterns = scanSourceCode(dir);

    // Layer 4: Reporting
    const report = {
      timestamp: new Date().toISOString(),
      scannedDirectory: dir,
      totalDependencies: dependencies.length,
      vulnerabilities,
      abandonedPackages,
      codeAntiPatterns,
    };

    if (format === 'text') {
      generateTextReport(report);
    } else {
      console.log(
        chalk.yellow(
          `[LeetGuard] ${format.toUpperCase()} format generation is not fully implemented in this MVP. Showing text fallback:`,
        ),
      );
      generateTextReport(report);
    }
  });

program.parse();
