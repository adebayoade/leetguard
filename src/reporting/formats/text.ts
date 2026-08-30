import { SecurityReport, Finding } from '../../types/index.js';
import chalk from 'chalk';
import Table from 'cli-table3';

/**
 * Generates a human-readable text report of the security findings
 * and logs it directly to the console using Chalk for colorization.
 *
 * @param report - The aggregated security report data.
 */
export function generateTextReport(report: SecurityReport): void {
  const allFindings = [
    ...report.vulnerabilities,
    ...(report.abandonedPackages || []),
    ...report.codeAntiPatterns,
  ];

  // 1. Print Summary Statistics in Mockup format
  console.log(
    chalk.gray(
      `[INFO]  ${report.totalDependencies} packages resolved (${report.directDependenciesCount} direct, ${report.transitiveDependenciesCount} transitive)`,
    ),
  );

  const metaVulns = report.metadata?.vulnerabilities;

  if (report.vulnerabilities.length > 0 && metaVulns) {
    console.log(
      chalk.red(
        `[CRIT]  ${metaVulns.critical} critical CVEs found  |  [HIGH] ${metaVulns.high}  |  [MED] ${metaVulns.moderate}  |  [LOW] ${metaVulns.low}`,
      ),
    );
  } else if (report.vulnerabilities.length > 0) {
    const cveHigh = report.vulnerabilities.filter(
      (f) => (f.severity || '').toLowerCase() === 'high',
    ).length;
    const cveMed = report.vulnerabilities.filter((f) =>
      ['moderate', 'medium'].includes((f.severity || '').toLowerCase()),
    ).length;
    const cveLow = report.vulnerabilities.filter(
      (f) => (f.severity || '').toLowerCase() === 'low',
    ).length;
    const cveCrit = report.vulnerabilities.filter(
      (f) => (f.severity || '').toLowerCase() === 'critical',
    ).length;
    console.log(
      chalk.red(
        `[CRIT]  ${cveCrit} critical CVEs found  |  [HIGH] ${cveHigh}  |  [MED] ${cveMed}  |  [LOW] ${cveLow}`,
      ),
    );
  } else {
    console.log(chalk.green(`[CRIT]  0 CVEs found`));
  }

  if (report.abandonedPackages && report.abandonedPackages.length > 0) {
    console.log(
      chalk.yellow(
        `[WARN]  ${report.abandonedPackages.length} packages not updated in over 2 years or deprecated`,
      ),
    );
  } else {
    console.log(chalk.green(`[WARN]  0 abandoned packages found`));
  }

  if (report.codeAntiPatterns && report.codeAntiPatterns.length > 0) {
    const categories = new Set(report.codeAntiPatterns.map((f) => f.category)).size;
    console.log(chalk.red(`[SAST]  ${categories} categories of security anti-patterns detected`));
  } else {
    console.log(chalk.green(`[SAST]  0 security anti-patterns detected`));
  }

  const uniqueIsos = new Set(allFindings.map((f) => f.isoControl));
  if (uniqueIsos.size > 0) {
    console.log(chalk.green(`[ISO]   Controls triggered: ${Array.from(uniqueIsos).join('  ')}`));
  }

  console.log(chalk.gray(`[DONE]  Scan complete\n`));

  if (allFindings.length === 0) {
    console.log(
      chalk.green(`\n[✓] No critical anti-patterns, supply chain risks, or CVEs found. Great job!`),
    );
    return;
  }

  console.log(chalk.red(`\n[!] Detailed Findings:`));

  // 2. Group findings by Category
  const groupedFindings = allFindings.reduce(
    (acc, finding) => {
      if (!acc[finding.category]) acc[finding.category] = [];
      acc[finding.category].push(finding);
      return acc;
    },
    {} as Record<string, Finding[]>,
  );

  // 3. Print grouped findings beautifully using cli-table3
  for (const [category, findings] of Object.entries(groupedFindings)) {
    console.log(chalk.bold.magenta(`\n>> ${category}`));

    const table = new Table({
      head: [
        chalk.white.bold('Severity'),
        chalk.white.bold('ID / Package'),
        chalk.white.bold('Summary'),
        chalk.white.bold('Trace / Location'),
      ],
      wordWrap: true,
      wrapOnWordBoundary: true,
      colWidths: [14, 25, 45, 50],
      style: {
        head: [], // Disable default styling for colors to work properly
        border: ['gray'],
      },
    });

    findings.forEach((f) => {
      let sevColor = chalk.white;
      const s = (f.severity || '').toLowerCase();
      if (s === 'critical') sevColor = chalk.bgRed.white.bold;
      else if (s === 'high') sevColor = chalk.red.bold;
      else if (s === 'moderate' || s === 'medium') sevColor = chalk.yellow.bold;
      else if (s === 'low') sevColor = chalk.cyan;

      const pkgStr = f.packageName ? chalk.gray(f.packageName) : '';
      const idPkg = [f.id, pkgStr].filter(Boolean).join('\n');

      const summary = f.summary || f.details || '';

      let traceStr = '';
      if (f.traces && f.traces.length > 0) {
        const maxTraces = Math.min(f.traces.length, 3);
        for (let i = 0; i < maxTraces; i++) {
          // Keep traces readable by wrapping them with a generic prefix
          traceStr += `root > ${f.traces[i].slice(1).join(' > ')}\n`;
        }
        if (f.traces.length > 3) {
          traceStr += chalk.gray(`... +${f.traces.length - 3} more`);
        }
      } else if (f.location) {
        traceStr = f.location;
      } else {
        traceStr = chalk.gray('N/A');
      }

      table.push([sevColor(f.severity || 'Unknown'), idPkg, summary.trim(), traceStr.trim()]);
    });

    console.log(table.toString());
  }
}
