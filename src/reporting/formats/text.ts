import { SecurityReport, Finding } from '../../types/index.js';
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

  const allFindings = [
    ...report.vulnerabilities,
    ...(report.abandonedPackages || []),
    ...report.codeAntiPatterns,
  ];

  if (allFindings.length === 0) {
    console.log(
      chalk.green(`\n[✓] No critical anti-patterns, supply chain risks, or CVEs found. Great job!`),
    );
    return;
  }

  // 1. Print Summary Statistics
  const high = allFindings.filter((f) => f.severity === 'High').length;
  const medium = allFindings.filter((f) => f.severity === 'Medium').length;
  const low = allFindings.filter((f) => f.severity === 'Low').length;

  console.log(chalk.bold(`\n📊 Summary:`));
  if (high > 0) console.log(chalk.red(`  High Severity: ${high}`));
  if (medium > 0) console.log(chalk.yellow(`  Medium Severity: ${medium}`));
  if (low > 0) console.log(chalk.cyan(`  Low Severity: ${low}`));

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

  // 3. Print grouped findings beautifully
  for (const [category, findings] of Object.entries(groupedFindings)) {
    console.log(chalk.bold.magenta(`\n>> ${category}`));

    findings.forEach((f) => {
      const color =
        f.severity === 'High' ? chalk.red : f.severity === 'Medium' ? chalk.yellow : chalk.cyan;
      console.log(color(`  - [${f.severity}] ${f.patternName}`));
      console.log(`    Description: ${f.description}`);
      if (f.trace && f.trace.length > 0) {
        console.log(`    Trace: root ➔ ${f.trace.join(' ➔ ')}`);
      }
      if (f.location) {
        console.log(`    Location: ${f.location}`);
      }
      console.log(chalk.gray(`    ISO 27001 Mapping: ${f.isoControl}`));
      console.log(); // Spacing between items
    });
  }
}
