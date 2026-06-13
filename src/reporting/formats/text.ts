import { SecurityReport } from '../../types/index.js';
import chalk from 'chalk';

/**
 * Generates a human-readable text report of the security findings
 * and logs it directly to the console using Chalk for colorization.
 *
 * @param report - The aggregated security report data.
 */
export function generateTextReport(report: SecurityReport): void {
  console.log(chalk.bold.blue(`\n=== LeetGuard Security Report ===`));
  console.log(chalk.gray(`Scanned Directory: ${report.scannedDirectory}`));
  console.log(chalk.gray(`Timestamp: ${report.timestamp}`));
  console.log(chalk.gray(`Total Dependencies: ${report.totalDependencies}`));

  if (report.vulnerabilities.length > 0 || report.codeAntiPatterns.length > 0) {
    console.log(chalk.red(`\n[!] Issues Found:\n`));

    const allFindings = [...report.vulnerabilities, ...report.codeAntiPatterns];
    allFindings.forEach((f) => {
      const color = f.severity === 'High' ? chalk.red : chalk.yellow;
      console.log(color(`- [${f.severity}] ${f.category} (${f.patternName})`));
      console.log(`  Description: ${f.description}`);
      if (f.trace && f.trace.length > 0) {
        console.log(`  Trace: root -> ${f.trace.join(' -> ')}`);
      }
      console.log(chalk.cyan(`  ISO 27001 Mapping: ${f.isoControl}\n`));
    });
  } else {
    console.log(chalk.green(`\n[✓] No critical anti-patterns or CVEs found.`));
  }
}
