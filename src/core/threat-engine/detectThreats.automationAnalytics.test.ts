import { describe, expect, it } from 'vitest';
import { detectThreats } from './detectThreats';
import type { DiagramBoundary, DiagramEdge, DiagramNode } from '../model/types';
import { componentRegistry } from '../../component-library/defaultRegistry';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';

/**
 * 業務自動化 / iPaaS（AUTOMATION_PLATFORM）と分析基盤 / DWH（ANALYTICS_PLATFORM）の固有ルールの発火確認（2026-11-13）。
 * 連携先の資格情報の集約と、データ単位の権限（dataPermission）の未設定。
 */

const fire = (id: string, nodes: DiagramNode[], edges: DiagramEdge[]) => {
  const rule = BUNDLED_THREAT_LIBRARY.rules.find((r) => r.id === id);
  expect(rule).toBeDefined();
  return detectThreats({ nodes, edges, framework: 'ALL', rules: [rule!] });
};

const node = (id: string, type: DiagramNode['type'], extra: Partial<DiagramNode> = {}): DiagramNode => ({
  id,
  type,
  x: 0,
  y: 0,
  ...extra,
});
const edge = (source: string, target: string, extra: Partial<DiagramEdge> = {}): DiagramEdge => ({
  id: `${source}-${target}`,
  source,
  target,
  network: 'Internet',
  encryption: 'TLS',
  auth: 'Token',
  ...extra,
});

describe('component registry の宣言', () => {
  it('AUTOMATION_PLATFORM は log / accountReview、ANALYTICS_PLATFORM は dataPermission を持つ', () => {
    expect(componentRegistry.getPostureGroups('AUTOMATION_PLATFORM')).toEqual(
      expect.arrayContaining(['log', 'accountReview']),
    );
    expect(componentRegistry.acceptsPostureField('ANALYTICS_PLATFORM', 'dataPermission')).toBe(true);
    expect(componentRegistry.acceptsPostureField('DATABASE', 'dataPermission')).toBe(false);
  });
});

describe('automation-platform-credential-aggregation-001', () => {
  const id = 'automation-platform-credential-aggregation-001';

  it('AUTOMATION_PLATFORM から BACKEND_API へ outbound → 発火する', () => {
    const r = fire(id, [node('p', 'AUTOMATION_PLATFORM'), node('a', 'BACKEND_API')], [edge('p', 'a')]);
    expect(r).toHaveLength(1);
    expect(r[0].canonicalId).toBe('automation-platform-credential-aggregation');
  });

  it('CONNECTOR から同じ線 → 発火しない', () => {
    expect(fire(id, [node('c', 'CONNECTOR'), node('a', 'BACKEND_API')], [edge('c', 'a')])).toHaveLength(0);
  });

  it('連携先の線が無い AUTOMATION_PLATFORM → 発火しない', () => {
    expect(fire(id, [node('p', 'AUTOMATION_PLATFORM')], [])).toHaveLength(0);
  });
});

describe('analytics-data-permission-missing-001', () => {
  const id = 'analytics-data-permission-missing-001';

  it('dataPermission 未入力 → 発火し、仮定の印（posture）が付く', () => {
    const r = fire(id, [node('w', 'ANALYTICS_PLATFORM')], []);
    expect(r).toHaveLength(1);
    expect(r[0].canonicalId).toBe('analytics-data-permission-missing');
    expect(r[0].assumptionFlags).toEqual(['posture']);
  });

  it("dataPermission が 'None' → 発火する", () => {
    const n = node('w', 'ANALYTICS_PLATFORM', { posture: { dataPermission: 'None' } });
    expect(fire(id, [n], [])).toHaveLength(1);
  });

  it("dataPermission が 'Enforced' → 発火しない", () => {
    const n = node('w', 'ANALYTICS_PLATFORM', { posture: { dataPermission: 'Enforced' } });
    expect(fire(id, [n], [])).toHaveLength(0);
  });

  it('DATABASE → 発火しない（アプリが認可を担う）', () => {
    expect(fire(id, [node('d', 'DATABASE')], [])).toHaveLength(0);
  });
});

/** 新 2 型の追加時に判断を残した既存ルールの対象拡大（2026-11-13）。 */
describe('既存ルールの対象に新 2 型を足したもの', () => {
  const partner: DiagramBoundary = { id: 'bp', type: 'RECT', x: 200, y: 200, width: 200, height: 200, trustLevel: 'Partner' };

  it('agentic-endpoint-command-unmanaged-target: AUTOMATION_PLATFORM → 未管理端末で発火、管理端末では発火しない', () => {
    const id = 'agentic-endpoint-command-unmanaged-target-001';
    const p = node('p', 'AUTOMATION_PLATFORM');
    expect(fire(id, [p, node('d', 'PC', { managedState: 'Unmanaged' })], [edge('p', 'd')])).toHaveLength(1);
    expect(fire(id, [p, node('d', 'PC', { managedState: 'Managed' })], [edge('p', 'd')])).toHaveLength(0);
  });

  it('maestro-partner-supply-chain-tool: 取引先境界内の AUTOMATION_PLATFORM で発火、境界外では発火しない', () => {
    const rule = BUNDLED_THREAT_LIBRARY.rules.find((r) => r.id === 'maestro-partner-supply-chain-tool-001')!;
    const nodes = [node('s', 'AGENT', { x: 50, y: 50 }), node('p', 'AUTOMATION_PLATFORM', { x: 300, y: 300 })];
    const run = (boundaries: DiagramBoundary[]) =>
      detectThreats({ nodes, edges: [edge('s', 'p')], boundaries, framework: 'ALL', rules: [rule] });
    expect(run([partner])).toHaveLength(1);
    expect(run([])).toHaveLength(0);
  });

  it('api-downstream-cascading-failure: BACKEND_API から ANALYTICS_PLATFORM へ outbound で発火、線が無ければ発火しない', () => {
    const id = 'api-downstream-cascading-failure-001';
    const a = node('a', 'BACKEND_API');
    expect(fire(id, [a, node('w', 'ANALYTICS_PLATFORM')], [edge('a', 'w')])).toHaveLength(1);
    expect(fire(id, [a, node('w', 'ANALYTICS_PLATFORM')], [])).toHaveLength(0);
  });

  it('admin-console-bulk-export-unguarded: ADMIN_CONSOLE と ANALYTICS_PLATFORM がつながると発火、AUTOMATION_PLATFORM では発火しない', () => {
    const id = 'admin-console-bulk-export-unguarded-001';
    const c = node('c', 'ADMIN_CONSOLE');
    expect(fire(id, [c, node('w', 'ANALYTICS_PLATFORM')], [edge('c', 'w')])).toHaveLength(1);
    expect(fire(id, [c, node('p', 'AUTOMATION_PLATFORM')], [edge('c', 'p')])).toHaveLength(0);
  });
});
