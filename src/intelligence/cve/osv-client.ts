import { Finding, PackageDependency } from '../../types/index.js';
import { CVE_ISO_CONTROL } from '../iso-mapper.js';

import { getCache, setCache, versionedCacheKey } from '../../core/cache.js';
import chalk from 'chalk';
import { logger } from '../../core/logger.js';
import Cvss from 'cvss-calculator';

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
    const cacheKey = versionedCacheKey(`osv_${pkg.name}@${pkg.version}`);
    const cachedFindings = getCache<Finding[]>(cacheKey);

    if (cachedFindings !== null) {
      const isDirect = pkg.trace ? pkg.trace.length === 1 : false;
      const findingsWithTrace = cachedFindings.map((f) => ({
        ...f,
        traces: pkg.trace ? [pkg.trace] : [],
        isDirect,
      }));
      findings.push(...findingsWithTrace);
    } else {
      uncachedDeps.push(pkg);
    }
  }

  const cachedCount = dependencies.length - uncachedDeps.length;
  if (uncachedDeps.length === 0) {
    logger.log(
      chalk.blue(
        `[LeetGuard] OSV API: Checked ${dependencies.length} dependencies (all loaded from cache)`,
      ),
    );
    return findings; // All dependencies were served from cache
  } else {
    logger.log(
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

      // Collect all unique vuln IDs to fetch full details
      const vulnIdsToFetch = new Set<string>();
      data.results?.forEach((result: any) => {
        if (result.vulns) {
          result.vulns.forEach((v: any) => vulnIdsToFetch.add(v.id));
        }
      });

      // Fetch full details for these vulns
      const fullVulnsMap: Record<string, any> = {};
      if (vulnIdsToFetch.size > 0) {
        const fetchPromises = Array.from(vulnIdsToFetch).map(async (id) => {
          try {
            const res = await fetch(`https://api.osv.dev/v1/vulns/${id}`);
            if (res.ok) {
              const vulnData = await res.json();
              fullVulnsMap[id] = vulnData;
            }
          } catch (e) {
            console.error(`Failed to fetch full details for ${id}`, e);
          }
        });
        await Promise.all(fetchPromises);
      }

      // The results array matches the queries array index
      data.results?.forEach((result: any, index: number) => {
        const pkg = chunkDeps[index];
        const cacheKey = versionedCacheKey(`osv_${pkg.name}@${pkg.version}`);
        const packageFindings: Finding[] = [];

        if (result.vulns && result.vulns.length > 0) {
          result.vulns.forEach((stubVuln: any) => {
            const vuln = fullVulnsMap[stubVuln.id] || stubVuln;

            // Check for available fixes in affected ranges, capturing the
            // actual fixed version string(s) rather than just a boolean flag
            const fixedVersionsSet = new Set<string>();
            if (vuln.affected) {
              for (const affected of vuln.affected) {
                if (affected.ranges) {
                  for (const range of affected.ranges) {
                    if (range.events) {
                      for (const event of range.events) {
                        if (event.fixed) fixedVersionsSet.add(event.fixed);
                      }
                    }
                  }
                }
              }
            }
            const fixedVersions = Array.from(fixedVersionsSet);
            const hasFix = fixedVersions.length > 0;

            // Extract CVSS vector if present
            let cvssObj = undefined;
            if (vuln.severity && Array.isArray(vuln.severity)) {
              const cvssV3 = vuln.severity.find((s: any) => s.type === 'CVSS_V3');
              if (cvssV3) {
                let score = 0;
                try {
                  const calc = new Cvss(cvssV3.score);
                  const baseScore = calc.getBaseScore();
                  if (typeof baseScore === 'number' && !isNaN(baseScore)) {
                    score = baseScore;
                  }
                } catch (e) {
                  // Fallback to 0 if parsing fails
                }
                cvssObj = { score, vectorString: cvssV3.score };
              }
            }

            // Extract severity and CWE from database_specific
            const dbSpecific = vuln.database_specific || {};
            const extractedSeverity = dbSpecific.severity || 'Unknown';
            const cweIds = dbSpecific.cwe_ids || [];
            const aliases = vuln.aliases || [];

            packageFindings.push({
              packageName: pkg.name,
              packageVersion: pkg.version,
              summary: vuln.summary,
              details: vuln.details,
              category: 'Injection & Dynamic Execution',
              id: vuln.id,
              severity: extractedSeverity,
              isoControl: CVE_ISO_CONTROL,
              fixAvailable: hasFix,
              fixedVersions: hasFix ? fixedVersions : undefined,
              cvss: cvssObj,
              cwe: cweIds,
              aliases,
              url: `https://osv.dev/vulnerability/${vuln.id}`,
            });
          });
        }

        // Cache the generic findings WITHOUT the project-specific trace
        setCache(cacheKey, packageFindings, 12);

        // Add the trace for the current run
        const isDirect = pkg.trace ? pkg.trace.length === 1 : false;
        const findingsWithTrace = packageFindings.map((f) => ({
          ...f,
          traces: pkg.trace ? [pkg.trace] : [],
          isDirect,
        }));
        findings.push(...findingsWithTrace);
      });
    } catch (error) {
      console.error(`Failed to query OSV API (Chunk ${i}):`, error);
    }
  }

  // Deduplicate findings by CVE ID and package name/version
  const groupedFindings = new Map<string, Finding>();
  for (const f of findings) {
    const key = `${f.id}|${f.packageName}@${f.packageVersion}`;
    if (groupedFindings.has(key)) {
      const existing = groupedFindings.get(key)!;
      if (f.traces && f.traces.length > 0) {
        existing.traces = existing.traces || [];
        existing.traces.push(f.traces[0]);
      }
      if (f.isDirect) {
        existing.isDirect = true;
      }
    } else {
      groupedFindings.set(key, f);
    }
  }

  return Array.from(groupedFindings.values());
}
