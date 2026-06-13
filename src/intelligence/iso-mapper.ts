import { AntiPatternCategory } from '../types/index.js';

export const ISOMap: Record<string, string> = {
  'eval() usage': 'A.14.2.1 Secure development policy',
  'new Function()': 'A.14.2.1 Secure development policy',
  'unvalidated input passed to dynamic contexts': 'A.14.2.5 Secure system engineering principles',
  'hardcoded secrets and API keys': 'A.8.2.3 Handling of assets',
  'sensitive data in console.log':
    'A.12.1.4 Separation of development, testing and operational environments',
  'insecure AsyncStorage': 'A.14.1.2 Securing application services on public networks',
  'missing HTTPS in hardcoded API URLs': 'A.13.2.1 Information transfer policies and procedures',
  'unvalidated WebView URIs': 'A.14.1.2 Securing application services on public networks',
  'unvalidated deep link parameters': 'A.14.2.5 Secure system engineering principles',
  'missing input validation on navigation props': 'A.14.2.5 Secure system engineering principles',
};

/**
 * Retrieves the corresponding ISO 27001 Annex A control for a specific
 * security anti-pattern. Defaults to 'Secure development policy' if unmapped.
 *
 * @param patternName - The name of the security anti-pattern or finding.
 * @returns The string description of the ISO 27001 control.
 */
export function getIsoControl(patternName: string): string {
  return ISOMap[patternName] || 'A.14.2.1 Secure development policy';
}
