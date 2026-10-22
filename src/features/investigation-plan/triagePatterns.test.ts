import { describe, expect, it } from 'vitest';
import { buildTriagePatterns, TRIAGE_PATTERNS_FORMAT } from './triagePatterns';
import { getInvestigationViewpoints } from './viewpoints';

describe('buildTriagePatterns', () => {
  const viewpoints = getInvestigationViewpoints('ja');
  const file = buildTriagePatterns(viewpoints);

  it('has the documented shape', () => {
    expect(file.format).toBe(TRIAGE_PATTERNS_FORMAT);
    expect(file.version).toBe(1);
    expect(file.id).toBeTruthy();
    expect(file.logPatterns.length).toBeGreaterThan(0);
    for (const p of file.logPatterns) {
      expect(p.id).toBeTruthy();
      expect(p.category).toBeTruthy();
      expect(typeof p.priority).toBe('number');
    }
    expect(file.accessLog?.method).toBe('POST');
    expect(file.accessLog?.statuses).toEqual([500, 502, 503, 504]);
    expect(file.webroot?.extensions).toContain('.php');
    expect(new Set(file.logPatterns.map((p) => p.id)).size).toBe(file.logPatterns.length);
  });

  it('has only valid regular expressions (case-insensitive, as the tool applies them)', () => {
    for (const p of file.logPatterns) {
      expect(() => new RegExp(p.regex, 'i'), p.id).not.toThrow();
    }
    const kernel = file.logPatterns.find((p) => p.id === 'kernel-oom-killed-process');
    expect(new RegExp(kernel?.regex ?? '', 'i').test('Out of memory: Killed process 123')).toBe(true);
  });

  it('keeps tools.triage out of the velociraptor steps', () => {
    const vp = viewpoints.find((v) => v.tools?.triage);
    expect(vp?.id).toBe('code-execution');
    expect(vp?.tools?.velociraptor?.length).toBeGreaterThan(0);
  });
});
