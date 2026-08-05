import { SecurityReport, Finding } from '../../types/index.js';
import crypto from 'crypto';

/**
 * Generates an HTML formatted string of the security report modeled as an NCR.
 * This outputs raw HTML to stdout, which can be redirected to a file.
 *
 * @param report - The aggregated security report data.
 */
export function generateHtmlReport(report: SecurityReport): void {
  const allFindings = [
    ...report.vulnerabilities,
    ...(report.abandonedPackages || []),
    ...report.codeAntiPatterns,
  ];

  const reportId = `NCR-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  const date = new Date(report.timestamp).toISOString().split('T')[0];

  const majors = allFindings.filter((f) => f.severity === 'High').length;
  const minors = allFindings.filter((f) => f.severity === 'Medium').length;
  const observations = allFindings.filter((f) => f.severity === 'Low').length;

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ISO/IEC 27001 NON-CONFORMITY REPORT (NCR)</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #111827;
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem;
            background-color: #f3f4f6;
        }
        .page {
            background: white;
            padding: 3rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            margin-bottom: 2rem;
        }
        .header {
            text-align: center;
            padding-bottom: 2rem;
            border-bottom: 4px solid #dc2626;
            margin-bottom: 2rem;
        }
        .header h1 {
            color: #dc2626;
            margin: 0 0 1rem 0;
            font-size: 1.8rem;
            text-transform: uppercase;
        }
        .meta-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 2rem;
        }
        .meta-table td {
            padding: 0.5rem;
            border: 1px solid #e5e7eb;
        }
        .meta-table td:first-child {
            font-weight: bold;
            background: #f9fafb;
            width: 30%;
        }
        .summary-box {
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            padding: 1.5rem;
            margin-bottom: 3rem;
        }
        .summary-box h2 {
            margin-top: 0;
            font-size: 1.2rem;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 0.5rem;
        }
        .ncr-card {
            border: 2px solid #111827;
            margin-bottom: 2rem;
            page-break-inside: avoid;
        }
        .ncr-header {
            background: #111827;
            color: white;
            padding: 0.75rem 1rem;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
        }
        .ncr-body {
            padding: 0;
        }
        .ncr-row {
            display: flex;
            border-bottom: 1px solid #e5e7eb;
        }
        .ncr-row:last-child {
            border-bottom: none;
        }
        .ncr-label {
            font-weight: bold;
            background: #f9fafb;
            padding: 0.75rem 1rem;
            width: 30%;
            border-right: 1px solid #e5e7eb;
        }
        .ncr-value {
            padding: 0.75rem 1rem;
            width: 70%;
        }
        .trace {
            font-family: monospace;
            background: #f3f4f6;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.85rem;
        }
        .status-compliant {
            text-align: center;
            color: #166534;
            background: #dcfce7;
            padding: 2rem;
            font-size: 1.2rem;
            font-weight: bold;
            border-radius: 8px;
        }
        @media print {
            body { background: white; padding: 0; }
            .page { box-shadow: none; padding: 0; }
        }
    </style>
</head>
<body>
    <div class="page">
        <div class="header">
            <h1>ISO/IEC 27001 Non-Conformity Report</h1>
        </div>

        <table class="meta-table">
            <tr>
                <td>Report ID</td>
                <td>${reportId}</td>
            </tr>
            <tr>
                <td>Date of Audit</td>
                <td>${date}</td>
            </tr>
            <tr>
                <td>Audited System / Target</td>
                <td>${report.scannedDirectory}</td>
            </tr>
            <tr>
                <td>Total Dependencies Audited</td>
                <td>${report.totalDependencies}</td>
            </tr>
        </table>

        ${
          allFindings.length === 0
            ? '<div class="status-compliant">[✓] Audit Complete: Zero non-conformities detected. System is compliant.</div>'
            : `
        <div class="summary-box">
            <h2>Audit Summary</h2>
            <p><strong>Major Non-Conformities (High Severity):</strong> <span style="color: #dc2626">${majors}</span></p>
            <p><strong>Minor Non-Conformities (Medium Severity):</strong> <span style="color: #d97706">${minors}</span></p>
            <p><strong>Observations (Low Severity):</strong> <span style="color: #2563eb">${observations}</span></p>
        </div>

        <h2>Detailed Findings</h2>
        ${allFindings
          .map((f, index) => {
            const findingId = `${reportId}-${String(index + 1).padStart(3, '0')}`;
            const ncrType =
              f.severity === 'High'
                ? 'MAJOR NON-CONFORMITY'
                : f.severity === 'Medium'
                  ? 'MINOR NON-CONFORMITY'
                  : 'OBSERVATION';

            let evidence = 'Identified in project configuration/dependencies.';
            if (f.trace && f.trace.length > 0) {
              evidence = `Dependency Trace: <span class="trace">root ➔ ${f.trace.join(' ➔ ')}</span>`;
            } else if (f.location) {
              evidence = `Source Code Location: <span class="trace">${f.location}</span>`;
            }

            return `
        <div class="ncr-card">
            <div class="ncr-header">
                <span>Finding ID: ${findingId}</span>
                <span>[${ncrType}]</span>
            </div>
            <div class="ncr-body">
                <div class="ncr-row">
                    <div class="ncr-label">ISO 27001 Control Ref</div>
                    <div class="ncr-value"><strong>${f.isoControl}</strong></div>
                </div>
                <div class="ncr-row">
                    <div class="ncr-label">Category</div>
                    <div class="ncr-value">${f.category}</div>
                </div>
                <div class="ncr-row">
                    <div class="ncr-label">Description of Non-Conformity</div>
                    <div class="ncr-value">${f.description} (${f.patternName})</div>
                </div>
                <div class="ncr-row">
                    <div class="ncr-label">Objective Evidence</div>
                    <div class="ncr-value">${evidence}</div>
                </div>
                <div class="ncr-row">
                    <div class="ncr-label">Corrective Action Required</div>
                    <div class="ncr-value">${f.severity !== 'Low' ? '<strong>Yes</strong>' : 'Recommended'}</div>
                </div>
            </div>
        </div>
        `;
          })
          .join('')}
        `
        }
    </div>
</body>
</html>
  `;

  // Output the pure HTML string directly to stdout
  console.log(html.trim());
}
