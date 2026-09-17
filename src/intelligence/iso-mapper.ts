export const ISOMap: Record<string, string> = {
  // Injection & Dynamic Execution — maps to A.8.28 Secure coding
  'eval() usage': 'A.8.28 Secure coding',
  'new Function()': 'A.8.28 Secure coding',

  // Data Exposure — maps to A.8.28 Secure coding
  'hardcoded secrets and API keys': 'A.8.28 Secure coding',
  'sensitive data in console.log': 'A.8.28 Secure coding',
  'insecure AsyncStorage': 'A.8.28 Secure coding',

  // Transport & Communication — maps to A.8.28 Secure coding
  'missing HTTPS in hardcoded API URLs': 'A.8.28 Secure coding',

  // React Native Mobile Risks — maps to A.8.29 Security testing
  'unvalidated WebView URIs': 'A.8.29 Security testing in development and acceptance',

  // Supply Chain — maps to A.5.22 Supplier monitoring
  'Abandoned Package': 'A.5.22 Monitoring, review and change management of supplier services',
};

// CVE findings from OSV map to A.8.8 Management of technical vulnerabilities
export const CVE_ISO_CONTROL = 'A.8.8 Management of technical vulnerabilities';

/**
 * Retrieves the corresponding ISO 27001:2022 Annex A control for a specific
 * security anti-pattern. Defaults to A.8.28 Secure coding if unmapped.
 *
 * @param patternName - The name of the security anti-pattern or finding.
 * @returns The string description of the ISO 27001:2022 control.
 */
export function getIsoControl(patternName: string): string {
  return ISOMap[patternName] || 'A.8.28 Secure coding';
}
