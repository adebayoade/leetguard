import { SecurityReport, Finding } from '../../types/index.js';
import chalk from 'chalk';

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
  console.log(chalk.gray(`[INFO]  ${report.totalDependencies} packages resolved (${report.directDependenciesCount} direct, ${report.transitiveDependenciesCount} transitive)`));

  const cveHigh = report.vulnerabilities.filter(f => f.severity === 'High').length;
  const cveMed = report.vulnerabilities.filter(f => f.severity === 'Medium').length;
  const cveLow = report.vulnerabilities.filter(f => f.severity === 'Low').length;
  
  if (report.vulnerabilities.length > 0) {
    console.log(chalk.red(`[CRIT]  ${report.vulnerabilities.length} critical CVEs found  |  [HIGH] ${cveHigh}  |  [MED] ${cveMed}  |  [LOW] ${cveLow}`));
  } else {
    console.log(chalk.green(`[CRIT]  0 CVEs found`));
  }

  if (report.abandonedPackages && report.abandonedPackages.length > 0) {
    console.log(chalk.yellow(`[WARN]  ${report.abandonedPackages.length} packages not updated in over 2 years or deprecated`));
  } else {
    console.log(chalk.green(`[WARN]  0 abandoned packages found`));
  }

  if (report.codeAntiPatterns && report.codeAntiPatterns.length > 0) {
    const categories = new Set(report.codeAntiPatterns.map(f => f.category)).size;
    console.log(chalk.red(`[SAST]  ${categories} categories of security anti-patterns detected`));
  } else {
    console.log(chalk.green(`[SAST]  0 security anti-patterns detected`));
  }

  const uniqueIsos = new Set(allFindings.map(f => f.isoControl));
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
