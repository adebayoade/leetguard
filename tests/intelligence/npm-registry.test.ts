import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkAbandonedPackages } from '../../src/intelligence/abandonment/npm-registry.js';

describe('checkAbandonedPackages', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('should flag a package as abandoned if it has not been updated in >2 years', async () => {
    // Mock date to 2026-06-13
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-06-13T00:00:00Z'));

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        time: { modified: '2023-01-01T00:00:00Z' }, // 3+ years old
      }),
    } as any);

    const findings = await checkAbandonedPackages(['old-package']);
    expect(findings.length).toBe(1);
    expect(findings[0].category).toBe('Supply Chain Risk');
    expect(findings[0].patternName).toBe('Abandoned Package');

    vi.useRealTimers();
  });

  it('should NOT flag a package as abandoned if updated recently', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-06-13T00:00:00Z'));

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        time: { modified: '2026-01-01T00:00:00Z' }, // < 1 year old
      }),
    } as any);

    const findings = await checkAbandonedPackages(['fresh-package']);
    expect(findings.length).toBe(0);

    vi.useRealTimers();
  });

  it('should handle network errors gracefully without throwing', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Network Error'));

    const findings = await checkAbandonedPackages(['error-package']);
    expect(findings.length).toBe(0);
  });
});
