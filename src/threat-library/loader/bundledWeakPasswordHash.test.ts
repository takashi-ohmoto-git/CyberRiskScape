import { describe, expect, it } from 'vitest';
import { BUNDLED_THREAT_LIBRARY } from './bundledLibrary';
import { detectThreats } from '../../core/threat-engine/detectThreats';
import type { DiagramNode } from '../../core/model/types';

const RULE_ID = 'identity-weak-password-hash-001';
const rules = BUNDLED_THREAT_LIBRARY.rules.filter((rule) => rule.id === RULE_ID);

const store = (type: string): DiagramNode => ({ id: 'store', type, x: 0, y: 0 });
const inside = (type: string): DiagramNode => ({
  id: 'child',
  type,
  x: 0,
  y: 0,
  parentId: 'store',
});
const run = (nodes: DiagramNode[]) =>
  detectThreats({ nodes, edges: [], framework: 'ALL', rules });

describe('identity-weak-password-hash-001', () => {
  it('同梱ライブラリに 1 件ある', () => {
    expect(rules).toHaveLength(1);
  });

  it.each(['DATABASE', 'DB', 'DATA_STORE', 'DIRECTORY'])(
    '%s が資格情報を内包する → 発火する',
    (type) => {
      expect(run([store(type), inside('CREDENTIAL')])).toHaveLength(1);
    },
  );

  it('内包が無い・資格情報以外の内包 → 発火しない', () => {
    expect(run([store('DATABASE')])).toHaveLength(0);
    expect(run([store('DATABASE'), inside('PERSONAL_INFO')])).toHaveLength(0);
  });

  it('対象外の型が資格情報を内包する → 発火しない', () => {
    expect(run([store('SECRETS_VAULT'), inside('CREDENTIAL')])).toHaveLength(0);
  });
});
