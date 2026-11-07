import { describe, expect, it } from 'vitest';
import { detectThreats } from './detectThreats';
import type { DiagramBoundary, DiagramNode } from '../model/types';
import { ThreatRuleSchema, type ThreatRule } from '../../threat-library/schema/threatRule';

/**
 * 管理境界の軸（ノード `managementBoundary`）。
 *
 * 押さえる点：
 * - 管理境界（MANAGEMENT）の外のノードでは不成立。
 * - 同じ管理境界の「他の」ノードの型・環境で成立する。別の管理境界のノードは見ない。
 * - 自ノードの環境は所属区画から。区画外は Unknown。
 */

const account: DiagramBoundary = {
  id: 'acct',
  type: 'MANAGEMENT',
  x: 0,
  y: 0,
  width: 1000,
  height: 500,
  trustLevel: 'Internal',
};
const otherAccount: DiagramBoundary = { ...account, id: 'acct2', x: 2000 };
const devSeg: DiagramBoundary = {
  id: 'dev',
  type: 'ROUNDED_DASHED',
  x: 500,
  y: 0,
  width: 400,
  height: 400,
  trustLevel: 'Internal',
  microTrust: 'Development',
  microSegmentationStatus: '未適用',
  sensitiveData: '無し',
};

const db: DiagramNode = { id: 'db', type: 'DATABASE', x: 100, y: 100 };
const ci: DiagramNode = { id: 'ci', type: 'CI_PIPELINE', x: 100, y: 300 };
const devDb: DiagramNode = { id: 'devDb', type: 'DATABASE', x: 600, y: 100 };
const db2: DiagramNode = { id: 'db2', type: 'DATABASE', x: 2100, y: 100 };
const outside: DiagramNode = { id: 'outside', type: 'DATABASE', x: 5000, y: 5000 };

function rule(managementBoundary: Record<string, unknown>): ThreatRule {
  return ThreatRuleSchema.parse({
    id: 'r',
    framework: 'STRIDE',
    category: 'Elevation of Privilege',
    severity: 'High',
    description: 'base',
    appliesTo: { kind: 'node', nodeType: 'DATABASE', connection: { required: false }, managementBoundary },
  });
}

const subjects = (r: ThreatRule, nodes: DiagramNode[], boundaries: DiagramBoundary[]) =>
  detectThreats({ nodes, edges: [], framework: 'ALL', rules: [r], boundaries })
    .map((t) => t.subject?.id)
    .sort();

describe('node appliesTo.managementBoundary', () => {
  it('同じ管理境界に CI が同居 → 発火。管理境界の外と別の管理境界には出ない', () => {
    const r = rule({ cohabitantType: ['CI_PIPELINE'] });
    expect(subjects(r, [db, ci, db2, outside], [account, otherAccount])).toEqual(['db']);
  });

  it('管理境界を描かない図 → 発火しない', () => {
    const r = rule({ cohabitantType: ['CI_PIPELINE'] });
    expect(subjects(r, [db, ci], [])).toEqual([]);
  });

  it('開発区画のノードとの同居 → cohabitantEnvironment で発火', () => {
    const r = rule({ cohabitantEnvironment: ['Development'] });
    expect(subjects(r, [db, devDb], [account, devSeg])).toEqual(['db']);
  });

  it('selfEnvironment: 区画外は Unknown として当たり、開発区画の自ノードは外れる', () => {
    const r = rule({ selfEnvironment: ['Production', 'Unknown'], cohabitantType: ['CI_PIPELINE'] });
    expect(subjects(r, [db, ci, devDb], [account, devSeg])).toEqual(['db']);
  });

  it('自分自身は同居相手に数えない', () => {
    const r = rule({ cohabitantType: ['DATABASE'] });
    expect(subjects(r, [db], [account])).toEqual([]);
  });

  it('cohabitantType も cohabitantEnvironment も無い条件はスキーマで拒否', () => {
    expect(() => rule({ selfEnvironment: ['Production'] })).toThrow();
  });
});
