import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { describe, expect, it } from 'vitest';
import { ATTACK_MATRIX, ATTACK_NAMES_JA, localizedName } from './attackMatrix';
import { extractAttackTechniqueIds } from '../attack-navigator/buildNavigatorLayer';

const m = ATTACK_MATRIX;
const subs = [...m.techniques.values()].flatMap((t) => t.subtechniques);

describe('ATT&CK マトリクス（データ整合）', () => {
  it('件数が固定値と一致する（版を上げたら意図的に更新）', () => {
    expect(m.tactics).toHaveLength(15);
    expect(m.techniques.size).toBe(227);
    expect(subs).toHaveLength(479);
    expect(m.tactics.map((t) => t.techniques.length)).toEqual([12, 9, 11, 22, 22, 13, 31, 18, 18, 34, 9, 17, 18, 10, 15]);
  });

  it('ID が重複しない', () => {
    const ids = [...m.tactics.map((t) => t.id), ...m.techniques.keys(), ...subs.map((s) => s.id)];
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('戦術が参照するテクニックはすべて存在し、全テクニックがいずれかの戦術に属する', () => {
    const raw = parseYaml(readFileSync(join('data', 'attack-matrix', 'enterprise-attack.yaml'), 'utf8')) as {
      tactics: { techniques: string[] }[];
    };
    const referenced = new Set(raw.tactics.flatMap((t) => t.techniques));
    for (const id of referenced) expect(m.techniques.has(id), id).toBe(true);
    for (const id of m.techniques.keys()) expect(referenced.has(id), id).toBe(true);
  });

  it('サブテクニックの ID は親 ID + .NNN', () => {
    for (const t of m.techniques.values()) {
      for (const s of t.subtechniques) expect(s.id.startsWith(`${t.id}.`) && /^\d{3}$/.test(s.id.slice(t.id.length + 1)), s.id).toBe(true);
    }
  });

  it('脅威ライブラリが参照する ATT&CK ID はすべてマトリクスに存在する（廃止 ID 検知）', () => {
    const dir = join('data', 'threat-library');
    const missing: string[] = [];
    for (const f of readdirSync(dir).filter((x) => x.endsWith('.yaml'))) {
      const text = readFileSync(join(dir, f), 'utf8');
      // references の title / url だけでなく本文も含め、行ごとに共通の抽出関数を通す。
      for (const id of extractAttackTechniqueIds([{ title: text }])) {
        if (!m.techniques.has(id) && !m.subToParent.has(id)) missing.push(`${f}: ${id}`);
      }
    }
    expect(missing).toEqual([]);
  });

  it('日本語訳が全 ID に過不足なくあり、空でない', () => {
    const allIds = new Set([...m.tactics.map((t) => t.id), ...m.techniques.keys(), ...subs.map((s) => s.id)]);
    const missing = [...allIds].filter((id) => !ATTACK_NAMES_JA.get(id)?.trim());
    const extra = [...ATTACK_NAMES_JA.keys()].filter((id) => !allIds.has(id));
    expect({ missing, extra }).toEqual({ missing: [], extra: [] });
  });

  it('localizedName は訳が無ければ英語名にフォールバックする', () => {
    expect(localizedName('T1078', 'en')).toBe(m.techniques.get('T1078')?.name);
    expect(localizedName('T9999', 'ja')).toBe('T9999');
  });
});
