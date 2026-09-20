import { describe, expect, it } from 'vitest';
import { detectThreats } from './detectThreats';
import { authProviderRoleOf, buildAuthProviderClosure } from './authProviderClosure';
import type { DiagramEdge, DiagramNode } from '../model/types';
import type { ThreatRule } from '../../threat-library/schema/threatRule';

/**
 * ノード軸 `authProviderRole` とノードルールの `conditions`（[[plan]] §2.41）。
 *
 * 押さえる点：
 * - `authProviderRole` は `authProviderId` の参照グラフからの派生値で、図に保存しない。
 * - `conditions` は **発火の可否を変えない**（severity / description の上書きのみ）。
 * - 既存ルール（条件なし）の挙動は不変。
 */

const idpA: DiagramNode = { id: 'idpA', type: 'IDENTITY_PROVIDER', x: 0, y: 0 };
const idpB: DiagramNode = { id: 'idpB', type: 'IDENTITY_PROVIDER', x: 300, y: 0 };
const app: DiagramNode = { id: 'app', type: 'PROCESS', x: 0, y: 300 };
const db: DiagramNode = { id: 'db', type: 'DB', x: 300, y: 300 };

function edge(id: string, source: string, target: string, authProviderId?: string): DiagramEdge {
  return {
    id,
    source,
    target,
    auth: 'MFA',
    network: 'VPC',
    encryption: 'TLS',
    ...(authProviderId ? { authProviderId } : {}),
  };
}

/** 接続要件は既定（接続必須）。発行元として参照されていれば論理接続で満たされる。 */
function nodeRule(extra: Record<string, unknown>): ThreatRule {
  return {
    id: 'node-rule',
    framework: 'STRIDE',
    category: 'Denial of Service',
    severity: 'Medium',
    description: 'base description',
    appliesTo: { kind: 'node', nodeType: 'IDENTITY_PROVIDER', ...extra },
  } as ThreatRule;
}

const run = (rule: ThreatRule, nodes: DiagramNode[], edges: DiagramEdge[]) =>
  detectThreats({ nodes, edges, framework: 'ALL', rules: [rule] });

describe('authProviderRoleOf', () => {
  it('参照されている発行元が 1 つだけなら Sole', () => {
    const c = buildAuthProviderClosure([idpA, app], [edge('e1', 'app', 'app', 'idpA')]);
    expect(authProviderRoleOf(c, 'idpA')).toBe('Sole');
  });

  it('参照されている発行元が複数あれば Shared', () => {
    const c = buildAuthProviderClosure(
      [idpA, idpB, app, db],
      [edge('e1', 'app', 'db', 'idpA'), edge('e2', 'db', 'app', 'idpB')],
    );
    expect(authProviderRoleOf(c, 'idpA')).toBe('Shared');
    expect(authProviderRoleOf(c, 'idpB')).toBe('Shared');
  });

  it('一度も参照されていなければ Unused。発行元になり得ない型も Unused', () => {
    const c = buildAuthProviderClosure([idpA, idpB, app], [edge('e1', 'app', 'idpA', 'idpA')]);
    expect(authProviderRoleOf(c, 'idpB')).toBe('Unused');
    expect(authProviderRoleOf(c, 'app')).toBe('Unused');
  });
});

describe('node appliesTo.authProviderRole', () => {
  const soleRule = nodeRule({ authProviderRole: ['Sole'] });

  it('単独依存の発行元で発火する', () => {
    const found = run(soleRule, [idpA, app, db], [edge('e1', 'app', 'db', 'idpA')]);
    expect(found.map((t) => t.nodeId)).toEqual(['idpA']);
  });

  it('発行元が 2 つ参照されていれば発火しない（Shared）', () => {
    const found = run(
      soleRule,
      [idpA, idpB, app, db],
      [edge('e1', 'app', 'db', 'idpA'), edge('e2', 'db', 'app', 'idpB')],
    );
    expect(found).toEqual([]);
  });

  it('authProviderId が 1 つも宣言されていない図では発火しない（全ノードが Unused）', () => {
    const found = run(soleRule, [idpA, app, db], [edge('e1', 'app', 'db')]);
    expect(found).toEqual([]);
  });
});

describe('node appliesTo.conditions', () => {
  const rule = nodeRule({
    conditions: [{ when: { authProviderRole: ['Sole'] }, severity: 'High', description: 'sole!' }],
  });

  it('条件に一致すると severity / description を上書きする', () => {
    const found = run(rule, [idpA, app, db], [edge('e1', 'app', 'db', 'idpA')]);
    expect(found).toHaveLength(1);
    expect(found[0].severity).toBe('High');
    expect(found[0].description).toBe('sole!');
  });

  it('条件に一致しなければルールのデフォルトのまま（発火自体は変わらない）', () => {
    const found = run(
      rule,
      [idpA, idpB, app, db],
      [edge('e1', 'app', 'db', 'idpA'), edge('e2', 'db', 'app', 'idpB')],
    );
    expect(found.map((t) => t.nodeId).sort()).toEqual(['idpA', 'idpB']);
    expect(found.every((t) => t.severity === 'Medium')).toBe(true);
    expect(found.every((t) => t.description === 'base description')).toBe(true);
  });

  it('first-match-wins（先に書いたケースが勝つ）', () => {
    const multi = nodeRule({
      conditions: [
        { when: { authProviderRole: ['Sole'] }, severity: 'High' },
        { when: { authProviderRole: ['Sole'] }, severity: 'Critical' },
      ],
    });
    const found = run(multi, [idpA, app, db], [edge('e1', 'app', 'db', 'idpA')]);
    expect(found[0].severity).toBe('High');
  });

  it('severity だけ指定したケースは description を据え置く', () => {
    const sevOnly = nodeRule({
      conditions: [{ when: { authProviderRole: ['Sole'] }, severity: 'Critical' }],
    });
    const found = run(sevOnly, [idpA, app, db], [edge('e1', 'app', 'db', 'idpA')]);
    expect(found[0].severity).toBe('Critical');
    expect(found[0].description).toBe('base description');
  });

  it('conditions の when は nodeType でも分岐できる（anyOf 対象ルール向け）', () => {
    const anyOfRule: ThreatRule = {
      id: 'any-of-rule',
      framework: 'STRIDE',
      category: 'Denial of Service',
      severity: 'Low',
      description: 'base',
      appliesTo: {
        kind: 'node',
        anyOf: [{ nodeType: 'IDENTITY_PROVIDER' }, { nodeType: 'DB' }],
        connection: { required: false },
        conditions: [{ when: { nodeType: ['DB'] }, severity: 'High' }],
      },
    } as ThreatRule;
    const found = run(anyOfRule, [idpA, db], []);
    const byNode = new Map(found.map((t) => [t.nodeId, t.severity] as const));
    expect(byNode.get('db')).toBe('High');
    expect(byNode.get('idpA')).toBe('Low');
  });
});
