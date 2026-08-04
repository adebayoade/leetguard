import { SecurityReport } from '../../types/index.js';

/**
 * Generates a JSON formatted text string of the security report.
 * This outputs raw JSON to stdout, which is ideal for CI/CD integration.
 *
 * @param report - The aggregated security report data.
 */
export function generateJsonReport(report: SecurityReport): void {
  // Output the pure JSON string directly to stdout
  console.log(JSON.stringify(report, null, 2));
}
