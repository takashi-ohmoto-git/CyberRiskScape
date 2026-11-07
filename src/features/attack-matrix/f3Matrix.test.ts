import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { describe, expect, it } from 'vitest';
import { F3_MATRIX, localizedName } from './attackMatrix';

const m = F3_MATRIX;
const subs = [...m.techniques.values()].flatMap((t) => t.subtechniques);
const raw = parseYaml(readFileSync(join('data', 'attack-matrix', 'f3.yaml'), 'utf8')) as {
  tactics: { techniques: string[] }[];
  techniques: Record<string, unknown>[];
};

describe('MITRE F3 マトリクス（データ整合）', () => {
  it('件数と戦術の並びが固定値と一致する（版を上げたら意図的に更新）', () => {
    expect(m.version).toBe('1.2');
    expect(m.tactics.map((t) => t.id)).toEqual([
      'TA0043',
      'TA0042',
      'TA0001',
      'TA0005',
      'TA0112',
      'FA0001',
      'TA0002',
      'FA0002',
    ]);
    expect(m.techniques.size).toBe(83);
    expect(subs).toHaveLength(55);
  });

  it('ID が重複しない', () => {
    const ids = [...m.tactics.map((t) => t.id), ...m.techniques.keys(), ...subs.map((s) => s.id)];
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('戦術が参照するテクニックはすべて存在し、全テクニックがいずれかの戦術に属する', () => {
    const referenced = new Set(raw.tactics.flatMap((t) => t.techniques));
    for (const id of referenced) expect(m.techniques.has(id), id).toBe(true);
    for (const id of m.techniques.keys()) expect(referenced.has(id), id).toBe(true);
  });

  it('説明文を持たず、ATT&CK 再利用 ID（T…）は 27 件', () => {
    const json = JSON.stringify(raw);
    expect(json).not.toContain('description');
    for (const t of raw.techniques) expect(Object.keys(t).every((k) => ['id', 'name', 'subtechniques'].includes(k))).toBe(true);
    expect([...m.techniques.keys()].filter((id) => id.startsWith('T'))).toHaveLength(27);
  });

  it('名前は英語のまま（ATT&CK の和訳を当てない）', () => {
    expect(localizedName('TA0043', 'ja', m)).toBe('Reconnaissance');
  });
});
