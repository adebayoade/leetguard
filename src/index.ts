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
import { generateJsonReport } from './reporting/formats/json.js';
import { generateAuditReport } from './reporting/formats/audit.js';
import { generateHtmlReport } from './reporting/formats/html.js';
import { lookupCveBatch } from './intelligence/cve/osv-client.js';
import { checkAbandonedPackages } from './intelligence/abandonment/npm-registry.js';
import { scanSourceCode } from './intelligence/scanner/ast-scanner.js';
import { select } from '@inquirer/prompts';
import { logger } from './core/logger.js';

// Workaround for __dirname in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const program = new Command();

// Read package.json to get the version
const packageJsonPath = join(__dirname, '../package.json');
const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));

program
  .name('leetguard')
  .description('LeetGuard - Security Anti-Pattern Scanner for Node.js and React projects')
  .version(pkg.version)
  .addHelpText(
    'after',
    `
Examples:
  $ leetguard scan .
  $ leetguard scan /path/to/project --format text
  $ leetguard scan /path/to/project --format json
`,
  );

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

    logger.log(chalk.bold(`LeetGuard v${pkg.version}  |  Scanning project...`));

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

    logger.log(chalk.blue(`[LeetGuard] Scanning source code for anti-patterns...`));
    const codeAntiPatterns = scanSourceCode(dir);

    // Layer 4: Reporting
    const directCount = directDeps.length;
    const transitiveCount =
      dependencies.length > directCount ? dependencies.length - directCount : 0;

    let prodCount = 0;
    let devCount = 0;
    let optionalCount = 0;
    let peerCount = 0;
    let peerOptionalCount = 0;

    dependencies.forEach((dep) => {
      if (dep.dev) devCount++;
      else prodCount++;

      if (dep.peerOptional) {
        peerOptionalCount++;
      } else if (dep.peer) {
        peerCount++;
      } else if (dep.optional) {
        optionalCount++;
      }
    });

    const packageSeverities = new Map<string, number>();
    const sevWeight: Record<string, number> = {
      critical: 4,
      high: 3,
      moderate: 2,
      medium: 2,
      low: 1,
      info: 0,
    };
    const sevNames = ['info', 'low', 'moderate', 'high', 'critical'];

    vulnerabilities.forEach((v) => {
      const sevStr = (v.severity || '').toLowerCase();
      const weight = sevWeight[sevStr] ?? -1;

      // Update the direct vulnerable package
      if (v.packageName) {
        const currentMax = packageSeverities.get(v.packageName) ?? -2;
        if (weight > currentMax) {
          packageSeverities.set(v.packageName, weight);
        }
      }

      // Bubble up the vulnerability severity to all intermediate packages in the traces (just like npm audit does)
      if (v.traces) {
        v.traces.forEach((trace) => {
          // Skip the first element which is the root project itself
          for (let i = 1; i < trace.length; i++) {
            const tracePkg = trace[i];
            const tMax = packageSeverities.get(tracePkg) ?? -2;
            if (weight > tMax) {
              packageSeverities.set(tracePkg, weight);
            }
          }
        });
      }
    });

    let infoCount = 0;
    let lowCount = 0;
    let moderateCount = 0;
    let highCount = 0;
    let criticalCount = 0;

    for (const weight of packageSeverities.values()) {
      if (weight === 4) criticalCount++;
      else if (weight === 3) highCount++;
      else if (weight === 2) moderateCount++;
      else if (weight === 1) lowCount++;
      else if (weight === 0) infoCount++;
    }

    const uniquePackages = packageSeverities.size;

    const metadata = {
      vulnerabilities: {
        info: infoCount,
        low: lowCount,
        moderate: moderateCount,
        high: highCount,
        critical: criticalCount,
        total: uniquePackages,
        totalCVEs: vulnerabilities.length,
      },
      dependencies: {
        prod: prodCount,
        dev: devCount,
        optional: optionalCount,
        peer: peerCount,
        peerOptional: peerOptionalCount,
        total: dependencies.length,
      },
    };

    const report = {
      timestamp: new Date().toISOString(),
      scannedDirectory: dir,
      totalDependencies: dependencies.length,
      directDependenciesCount: directCount,
      transitiveDependenciesCount: transitiveCount,
      metadata,
      vulnerabilities,
      abandonedPackages,
      codeAntiPatterns,
    };

    if (format === 'text') {
      generateTextReport(report);
    } else if (format === 'json') {
      generateJsonReport(report);
    } else if (format === 'audit') {
      generateAuditReport(report);
    } else if (format === 'html') {
      generateHtmlReport(report);
    } else {
      logger.log(
        chalk.yellow(
          `[LeetGuard] ${format.toUpperCase()} format generation is not fully implemented in this MVP. Showing text fallback:`,
        ),
      );
      generateTextReport(report);
    }
  });

if (!process.argv.slice(2).length) {
  program.outputHelp();
  process.exit(0);
}

program.parse();
