import { describe, expect, it } from 'vitest';
import { detectThreats } from './detectThreats';
import type { DiagramNode } from '../model/types';
import { componentRegistry } from '../../component-library/defaultRegistry';
import { PostureMatchSchema, ThreatRuleSchema, type ThreatRule } from '../../threat-library/schema/threatRule';

/**
 * 運用状況（posture）軸と containsType 軸。ルールはこのテスト内のフィクスチャで、
 * data/threat-library には置かない。
 *
 * 押さえる点：
 * - 未設定は 'Unknown'（対策なし扱い）として評価し、`posture` フラグを付ける。
 * - ノードの型がそのフィールドのグループを宣言していなければ不成立。
 * - conditions で段階分けできる。containsType は子ノードの型で判定する。
 */

const db: DiagramNode = { id: 'db', type: 'DATABASE', x: 0, y: 0 };
const user: DiagramNode = { id: 'user', type: 'USER', x: 0, y: 0 };

function rule(appliesTo: Record<string, unknown>): ThreatRule {
  return ThreatRuleSchema.parse({
    id: 'posture-test',
    framework: 'STRIDE',
    category: 'Information Disclosure',
    severity: 'Medium',
    description: 'base',
    appliesTo: { kind: 'node', connection: { required: false }, ...appliesTo },
  });
}

const run = (r: ThreatRule, nodes: DiagramNode[]) =>
  detectThreats({ nodes, edges: [], framework: 'ALL', rules: [r] });

describe('component registry の posture 宣言', () => {
  it('DATABASE は log / encryptionAtRest を持ち、USER は持たない', () => {
    expect(componentRegistry.getPostureGroups('DATABASE')).toContain('log');
    expect(componentRegistry.acceptsPostureField('DATABASE', 'encryptionAtRest')).toBe(true);
    expect(componentRegistry.acceptsPostureField('USER', 'encryptionAtRest')).toBe(false);
  });

  it('公開サーバーと API ゲートウェイは logRetention（logCollection は持たない）', () => {
    for (const t of ['FRONT_END_SERVER', 'GATEWAY']) {
      expect(componentRegistry.getPostureGroups(t)).toContain('logRetention');
      expect(componentRegistry.acceptsPostureField(t, 'logRetention')).toBe(true);
      expect(componentRegistry.acceptsPostureField(t, 'logCollection')).toBe(false);
    }
  });

  it('SaaS は patch を持たない（提供者責任）', () => {
    expect(componentRegistry.acceptsPostureField('SAAS', 'patchStatus')).toBe(false);
    expect(componentRegistry.acceptsPostureField('SAAS', 'encryptionAtRest')).toBe(true);
  });
});

describe('PostureMatchSchema', () => {
  it('空オブジェクトと空配列を拒否する', () => {
    expect(PostureMatchSchema.safeParse({}).success).toBe(false);
    expect(PostureMatchSchema.safeParse({ logRetention: [] }).success).toBe(false);
  });

  it('Unknown を含められ、未知の値は拒否する', () => {
    expect(PostureMatchSchema.safeParse({ logRetention: ['Under90Days', 'Unknown'] }).success).toBe(true);
    expect(PostureMatchSchema.safeParse({ logRetention: ['Forever'] }).success).toBe(false);
  });

  it('lastReviewedAt は軸にできない（未知キーのみで空扱い）', () => {
    expect(PostureMatchSchema.safeParse({ lastReviewedAt: ['2026-10-10'] }).success).toBe(false);
  });
});

describe('posture 軸の判定', () => {
  const r = rule({ nodeType: 'DATABASE', posture: { encryptionAtRest: ['None', 'Unknown'] } });

  it('未設定は Unknown として一致し、posture フラグが付く', () => {
    const out = run(r, [db]);
    expect(out).toHaveLength(1);
    expect(out[0].assumptionFlags).toEqual(['posture']);
  });

  it('明示した値で一致した場合はフラグが付かない', () => {
    const out = run(r, [{ ...db, posture: { encryptionAtRest: 'None' } }]);
    expect(out).toHaveLength(1);
    expect(out[0].assumptionFlags).toBeUndefined();
  });

  it('対策ありの値は一致しない', () => {
    expect(run(r, [{ ...db, posture: { encryptionAtRest: 'CustomerManagedKey' } }])).toHaveLength(0);
  });

  it('Unknown を指定しないルールは、未設定ノードでは発火しない', () => {
    const strict = rule({ nodeType: 'DATABASE', posture: { encryptionAtRest: ['None'] } });
    expect(run(strict, [db])).toHaveLength(0);
    expect(run(strict, [{ ...db, posture: { encryptionAtRest: 'None' } }])).toHaveLength(1);
  });

  it('型がそのグループを宣言していなければ、未設定でも発火しない', () => {
    const onUser = rule({ nodeType: 'USER', posture: { encryptionAtRest: ['None', 'Unknown'] } });
    expect(run(onUser, [user])).toHaveLength(0);
    // 値が入っていても（入力できない属性なので）不成立
    expect(
      run(onUser, [{ ...user, posture: { encryptionAtRest: 'None' } }]),
    ).toHaveLength(0);
  });

  it('フィールド間は AND、配列内は OR', () => {
    const both = rule({
      nodeType: 'DATABASE',
      posture: { encryptionAtRest: ['None', 'Unknown'], logRetention: ['Under90Days', 'Under1Year'] },
    });
    const nodeOk: DiagramNode = { ...db, posture: { logRetention: 'Under1Year' } };
    const nodeNg: DiagramNode = { ...db, posture: { logRetention: 'OneYearOrMore' } };
    expect(run(both, [nodeOk])).toHaveLength(1);
    expect(run(both, [nodeNg])).toHaveLength(0);
  });

  it('lastReviewedAt / reviewNote は判定に影響しない', () => {
    const out = run(r, [{ ...db, posture: { lastReviewedAt: '2020-01-01', reviewNote: 'x' } }]);
    expect(out).toHaveLength(1);
    expect(out[0].assumptionFlags).toEqual(['posture']);
  });
});

describe('containsType 軸と conditions での段階分け', () => {
  const graded = rule({
    nodeType: 'DATABASE',
    posture: { encryptionAtRest: ['None', 'Unknown'] },
    conditions: [
      { when: { containsType: ['PERSONAL_INFO', 'CONFIDENTIAL_INFO'] }, severity: 'High' },
      { when: { posture: { logRetention: ['Under90Days'] } }, severity: 'Low' },
    ],
  });
  const pii: DiagramNode = { id: 'pii', type: 'PERSONAL_INFO', x: 0, y: 0, parentId: 'db' };

  it('子ノードの型が該当すれば severity を上げる', () => {
    expect(run(graded, [db, pii])[0].severity).toBe('High');
  });

  it('子がいない・別の型・別の親の子では上げない', () => {
    expect(run(graded, [db])[0].severity).toBe('Medium');
    const other: DiagramNode = { id: 'o', type: 'OTHER_DOCUMENT', x: 0, y: 0, parentId: 'db' };
    expect(run(graded, [db, other])[0].severity).toBe('Medium');
    const orphan: DiagramNode = { ...pii, parentId: 'someone-else' };
    expect(run(graded, [db, orphan])[0].severity).toBe('Medium');
  });

  it('conditions は first-match-wins で、posture 条件でも段階分けできる', () => {
    const shortLog: DiagramNode = { ...db, posture: { logRetention: 'Under90Days' } };
    expect(run(graded, [shortLog])[0].severity).toBe('Low');
    // 先に書いた containsType が優先される
    expect(run(graded, [shortLog, pii])[0].severity).toBe('High');
  });

  it('appliesTo の containsType は発火自体を絞る', () => {
    const only = rule({ nodeType: 'DATABASE', containsType: ['PERSONAL_INFO'] });
    expect(run(only, [db])).toHaveLength(0);
    expect(run(only, [db, pii])).toHaveLength(1);
  });

  it('conditions の when は posture / containsType のみでも有効（空は拒否）', () => {
    expect(() =>
      ThreatRuleSchema.parse({
        id: 'x',
        framework: 'STRIDE',
        category: 'c',
        severity: 'Low',
        description: 'd',
        appliesTo: { kind: 'node', nodeType: 'DATABASE', conditions: [{ when: {}, severity: 'High' }] },
      }),
    ).toThrow();
  });
});
