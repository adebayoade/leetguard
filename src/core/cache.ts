import { homedir } from 'os';
import { join } from 'path';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';

export interface CacheEntry<T> {
  value: T;
  expiresAt: number; // timestamp in milliseconds
}

const cacheDir = join(homedir(), '.leetguard');
const cacheFilePath = join(cacheDir, 'cache.json');

/**
 * Ensures that the cache directory and cache file exist.
 * Creates them if they are missing.
 */
function ensureCacheFile() {
  if (!existsSync(cacheDir)) {
    mkdirSync(cacheDir, { recursive: true });
  }
  if (!existsSync(cacheFilePath)) {
    writeFileSync(cacheFilePath, JSON.stringify({}), 'utf-8');
  }
}

/**
 * Reads the cache from the filesystem.
 *
 * @returns A dictionary of cached entries.
 */
function readCache(): Record<string, CacheEntry<any>> {
  ensureCacheFile();
  try {
    const data = readFileSync(cacheFilePath, 'utf-8');
    return JSON.parse(data);
  } catch {
    return {};
  }
}

/**
 * Writes the provided cache data to the filesystem.
 * Silently fails if write permissions are denied.
 *
 * @param data - The dictionary of cache entries to write.
 */
function writeCache(data: Record<string, CacheEntry<any>>) {
  ensureCacheFile();
  try {
    writeFileSync(cacheFilePath, JSON.stringify(data, null, 2), 'utf-8');
  } catch (e) {
    // Silently fail if cache can't be written (e.g. permissions)
  }
}

/**
 * Retrieves a value from the cache by its key.
 * If the entry has expired, it deletes the entry and returns null.
 *
 * @param key - The unique identifier for the cache entry.
 * @returns The cached value, or null if missing or expired.
 */
export function getCache<T>(key: string): T | null {
  const cache = readCache();
  const entry = cache[key];

  if (!entry) {
    return null;
  }

  if (Date.now() > entry.expiresAt) {
    // Expired
    delete cache[key];
    writeCache(cache);
    return null;
  }

  return entry.value as T;
}

/**
 * Sets a value in the cache with a specified Time-to-Live (TTL).
 *
 * @param key - The unique identifier for the cache entry.
 * @param value - The data to cache.
 * @param ttlHours - The number of hours until the cache entry expires.
 */
export function setCache<T>(key: string, value: T, ttlHours: number): void {
  const cache = readCache();
  cache[key] = {
    value,
    expiresAt: Date.now() + ttlHours * 60 * 60 * 1000,
  };
  writeCache(cache);
}

/**
 * Scans the cache for expired entries and removes them.
 * Writes the updated cache back to disk if changes were made.
 */
export function clearExpiredCache(): void {
  const cache = readCache();
  let hasChanges = false;
  const now = Date.now();

  for (const key of Object.keys(cache)) {
    if (now > cache[key].expiresAt) {
      delete cache[key];
      hasChanges = true;
    }
  }

  if (hasChanges) {
    writeCache(cache);
  }
}
