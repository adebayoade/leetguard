import { Finding } from '../../types/index.js';
import { getCache, setCache } from '../../core/cache.js';
import chalk from 'chalk';

const NPM_REGISTRY_URL = 'https://registry.npmjs.org';
const ABANDONED_THRESHOLD_MONTHS = 24;

/**
 * Checks a list of direct dependencies against the npm registry
 * to determine if they are abandoned (no updates in the last 24 months).
 * Utilizes the local filesystem cache to prevent duplicate requests.
 *
 * @param directDependencies - An array of package names to check.
 * @returns A promise resolving to an array of security findings for abandoned packages.
 */
export async function checkAbandonedPackages(directDependencies: string[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  const uncachedPackages: string[] = [];

  for (const pkgName of directDependencies) {
    const cacheKey = `npm_${pkgName}`;
    const cachedFindings = getCache<Finding[]>(cacheKey);
    if (cachedFindings !== null) {
      findings.push(...cachedFindings);
    } else {
      uncachedPackages.push(pkgName);
    }
  }

  const cachedCount = directDependencies.length - uncachedPackages.length;
  if (uncachedPackages.length === 0) {
    console.log(
      chalk.blue(
        `[LeetGuard] NPM Registry: Checked ${directDependencies.length} direct dependencies (all loaded from cache)`,
      ),
    );
    return findings;
  } else {
    console.log(
      chalk.blue(
        `[LeetGuard] NPM Registry: Checking ${uncachedPackages.length} packages for abandonment (${cachedCount} loaded from cache)...`,
      ),
    );
  }

  const CHUNK_SIZE = 10;

  for (let i = 0; i < uncachedPackages.length; i += CHUNK_SIZE) {
    const chunk = uncachedPackages.slice(i, i + CHUNK_SIZE);

    await Promise.all(
      chunk.map(async (pkgName) => {
        const cacheKey = `npm_${pkgName}`;
        const pkgFindings: Finding[] = [];

        try {
          const response = await fetch(`${NPM_REGISTRY_URL}/${pkgName}`);
          if (!response.ok) {
            setCache(cacheKey, [], 24); // Cache failures as empty so we don't spam 404s
            return;
          }

          const data = await response.json();
          const modifiedTime = data.time?.modified;

          if (modifiedTime) {
            const lastUpdated = new Date(modifiedTime);
            const now = new Date();
            const monthsDiff =
              (now.getFullYear() - lastUpdated.getFullYear()) * 12 +
              (now.getMonth() - lastUpdated.getMonth());

            if (monthsDiff >= ABANDONED_THRESHOLD_MONTHS) {
              pkgFindings.push({
                category: 'Supply Chain Risk',
                patternName: 'Abandoned Package',
                severity: 'Medium',
                description: `[${pkgName}] Package has not been updated in ${monthsDiff} months.`,
                isoControl: 'A.14.2.7', // Outsourced development
              });
            }
          }

          setCache(cacheKey, pkgFindings, 24);
          findings.push(...pkgFindings);
        } catch (error) {
          // Silent catch to prevent one failed network request from crashing the tool
          // Don't cache hard network errors, so we retry next time
        }
      }),
    );
  }

  return findings;
}
