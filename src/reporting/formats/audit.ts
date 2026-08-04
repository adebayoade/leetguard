import { SecurityReport, Finding } from '../../types/index.js';
import chalk from 'chalk';
import crypto from 'crypto';

/**
 * Generates an ISO 27001 compliant Non-Conformity Report (NCR) for audit purposes.
 *
 * @param report - The aggregated security report data.
 */
export function generateAuditReport(report: SecurityReport): void {
  const allFindings = [
    ...report.vulnerabilities,
    ...(report.abandonedPackages || []),
    ...report.codeAntiPatterns,
  ];

  const reportId = `NCR-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  const date = new Date(report.timestamp).toISOString().split('T')[0];

  console.log(chalk.bold.white.bgRed(`\n=== ISO/IEC 27001 NON-CONFORMITY REPORT (NCR) ===`));
  console.log(chalk.bold(`Report ID: `) + reportId);
  console.log(chalk.bold(`Date of Audit: `) + date);
  console.log(chalk.bold(`Audited System / Target: `) + report.scannedDirectory);
  console.log(chalk.bold(`Total Dependencies Audited: `) + report.totalDependencies);
  console.log(chalk.bold.white.bgRed(`=================================================`));

  if (allFindings.length === 0) {
    console.log(
      chalk.green(`\n[✓] Audit Complete: Zero non-conformities detected. System is compliant.`),
    );
    return;
  }

  const majors = allFindings.filter((f) => f.severity === 'High').length;
  const minors = allFindings.filter((f) => f.severity === 'Medium').length;
  const observations = allFindings.filter((f) => f.severity === 'Low').length;

  console.log(chalk.bold(`\n>> AUDIT SUMMARY:`));
  console.log(chalk.red(`  Major Non-Conformities (High Severity): ${majors}`));
  console.log(chalk.yellow(`  Minor Non-Conformities (Medium Severity): ${minors}`));
  console.log(chalk.cyan(`  Observations (Low Severity): ${observations}`));
  console.log(`\n-------------------------------------------------\n`);

  allFindings.forEach((f, index) => {
    const findingId = `${reportId}-${String(index + 1).padStart(3, '0')}`;
    const ncrType =
      f.severity === 'High'
        ? 'MAJOR NON-CONFORMITY'
        : f.severity === 'Medium'
          ? 'MINOR NON-CONFORMITY'
          : 'OBSERVATION';

    const color =
      f.severity === 'High' ? chalk.red : f.severity === 'Medium' ? chalk.yellow : chalk.cyan;

    console.log(color.bold(`Finding ID: ${findingId} [${ncrType}]`));
    console.log(chalk.bold(`ISO 27001 Control Ref: `) + f.isoControl);
    console.log(chalk.bold(`Category: `) + f.category);
    console.log(chalk.bold(`Description of Non-Conformity: `));
    console.log(`  ${f.description} (${f.patternName})`);

    console.log(chalk.bold(`Objective Evidence: `));
    if (f.trace && f.trace.length > 0) {
      console.log(`  Dependency Trace: root ➔ ${f.trace.join(' ➔ ')}`);
    } else if (f.location) {
      console.log(`  Source Code Location: ${f.location}`);
    } else {
      console.log(`  Identified in project configuration/dependencies.`);
    }

    console.log(
      chalk.bold(`Corrective Action Required: `) + (f.severity !== 'Low' ? 'Yes' : 'Recommended'),
    );
    console.log(`-------------------------------------------------\n`);
  });
}
