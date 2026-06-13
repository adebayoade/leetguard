import { Finding, PackageDependency } from '../../types/index.js';

import { getCache, setCache } from '../../core/cache.js';
import chalk from 'chalk';

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';

/**
 * Queries the Open Source Vulnerability (OSV) database for known CVEs
 * across a list of package dependencies.
 * Automatically utilizes the local filesystem cache and chunks requests
 * to respect the API limits.
 *
 * @param dependencies - An array of package dependencies to check.
 * @returns A promise resolving to an array of security findings.
 */
export async function lookupCveBatch(dependencies: PackageDependency[]): Promise<Finding[]> {
  if (dependencies.length === 0) return [];

  const findings: Finding[] = [];
  const uncachedDeps: PackageDependency[] = [];

  // Check cache first
  for (const pkg of dependencies) {
    const cacheKey = `osv_${pkg.name}@${pkg.version}`;
    const cachedFindings = getCache<Finding[]>(cacheKey);

    if (cachedFindings !== null) {
      const findingsWithTrace = cachedFindings.map((f) => ({ ...f, trace: pkg.trace }));
      findings.push(...findingsWithTrace);
    } else {
      uncachedDeps.push(pkg);
    }
  }

  const cachedCount = dependencies.length - uncachedDeps.length;
  if (uncachedDeps.length === 0) {
    console.log(
      chalk.blue(
        `[LeetGuard] OSV API: Checked ${dependencies.length} dependencies (all loaded from cache)`,
      ),
    );
    return findings; // All dependencies were served from cache
  } else {
    console.log(
      chalk.blue(
        `[LeetGuard] OSV API: Querying ${uncachedDeps.length} dependencies from network (${cachedCount} loaded from cache)...`,
      ),
    );
  }

  // Prepare batch queries for uncached dependencies
  const allQueries = uncachedDeps.map((pkg) => ({
    package: {
      name: pkg.name,
      ecosystem: 'npm',
    },
    version: pkg.version,
  }));

  const CHUNK_SIZE = 1000; // OSV limit per batch

  for (let i = 0; i < allQueries.length; i += CHUNK_SIZE) {
    const chunk = allQueries.slice(i, i + CHUNK_SIZE);
    const chunkDeps = uncachedDeps.slice(i, i + CHUNK_SIZE);

    try {
      const response = await fetch(OSV_BATCH_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ queries: chunk }),
      });

      if (!response.ok) {
        console.error(`OSV API Error (Chunk ${i}):`, response.statusText);
        continue;
      }

      const data = await response.json();

      // The results array matches the queries array index
      data.results?.forEach((result: any, index: number) => {
        const pkg = chunkDeps[index];
        const cacheKey = `osv_${pkg.name}@${pkg.version}`;
        const packageFindings: Finding[] = [];

        if (result.vulns && result.vulns.length > 0) {
          result.vulns.forEach((vuln: any) => {
            packageFindings.push({
              category: 'Injection & Dynamic Execution',
              patternName: vuln.id,
              severity: 'High',
              description: `[${pkg.name}@${pkg.version}] ${vuln.summary || vuln.details || 'Known Vulnerability'}`,
              isoControl: 'A.14.2.8',
            });
          });
        }

        // Cache the generic findings WITHOUT the project-specific trace
        setCache(cacheKey, packageFindings, 12);
        
        // Add the trace for the current run
        const findingsWithTrace = packageFindings.map((f) => ({ ...f, trace: pkg.trace }));
        findings.push(...findingsWithTrace);
      });
    } catch (error) {
      console.error(`Failed to query OSV API (Chunk ${i}):`, error);
    }
  }

  return findings;
}
