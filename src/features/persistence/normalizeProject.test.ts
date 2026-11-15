import { describe, expect, it } from 'vitest';
import { normalizeProject } from './normalizeProject';
import { PERSISTED_PROJECT_SCHEMA_VERSION } from './schema';
import { serializeProject } from './serialize';
import { EMPTY_LAYER, type Finding } from '../../core/model/types';

/** 深度レイヤー導入前の形（トップレベルに図を持つ）。 */
const LEGACY = {
  schemaVersion: PERSISTED_PROJECT_SCHEMA_VERSION,
  nodes: [
    { id: 'n1', type: 'USER', x: 10, y: 20 },
    { id: 'n2', type: 'LLM', x: 100, y: 200 },
  ],
  edges: [{ id: 'e1', source: 'n1', target: 'n2', auth: 'Password', network: 'VPC', encryption: 'TLS' }],
  boundaries: [],
  activeFramework: 'MAESTRO',
  dreadScores: {
    'rule-x-n1': { damage: 3, reproducibility: 2, exploitability: 2, affectedUsers: 1, discoverability: 3, at: 5 },
  },
  updatedAt: 1234,
};

const FINDING: Finding = {
  id: 'Example:f-1',
  source: { format: 'sarif', product: 'Example', importedAt: '2026-11-01T00:00:00Z' },
  externalId: 'f-1',
  identifiers: [{ scheme: 'cve', value: 'CVE-2026-0001' }],
  severity: 'High',
  canonicalIds: [],
};

describe('normalizeProject', () => {
  it('検証に通らない入力 → null', () => {
    expect(normalizeProject({ schemaVersion: 999 })).toBeNull();
    expect(normalizeProject('x')).toBeNull();
  });

  it('旧形式：トップレベルの図は L1 に移り、旧項目は残らない', () => {
    const out = normalizeProject(LEGACY)!;
    expect(out.layers?.L1.nodes.map((n) => n.id)).toEqual(['n1', 'n2']);
    expect(out.layers?.L1.edges).toHaveLength(1);
    expect(out.activeLayer).toBe('L1');
    expect('nodes' in out).toBe(false);
    expect('edges' in out).toBe(false);
    expect('boundaries' in out).toBe(false);
  });

  it('旧形式：seq を採番し、idCounters に記録する', () => {
    const out = normalizeProject(LEGACY)!;
    expect(out.layers?.L1.nodes.map((n) => n.seq)).toEqual([1, 2]);
    expect(out.idCounters?.L1).toEqual({ node: 2, edge: 1, boundary: 0 });
  });

  it('旧形式：dreadScores は riskScores になり、旧 framework 値は読み替える', () => {
    const out = normalizeProject(LEGACY)!;
    expect(out.riskScores).toEqual({
      'rule-x-n1': { damage: 3, affectedUsers: 1, reproducibility: 2, exploitability: 2, at: 5 },
    });
    expect('dreadScores' in out).toBe(false);
    expect(out.activeFramework).toBe('AgenticAI');
  });

  it('appVersion（保存した版の記録）は書き換えない。無いファイルには足さない', () => {
    expect(normalizeProject({ ...LEGACY, appVersion: '0.1.0' })!.appVersion).toBe('0.1.0');
    expect('appVersion' in normalizeProject(LEGACY)!).toBe(false);
  });

  it('updatedAt は変えない。2 回かけても結果は同じ', () => {
    const once = normalizeProject(LEGACY)!;
    expect(once.updatedAt).toBe(1234);
    expect(normalizeProject(once)).toEqual(once);
  });

  it('現行の形：図以外の項目（ID・判断・指摘・付加情報）はそのまま通る', () => {
    const current = serializeProject({
      projectId: '00000000-0000-4000-8000-0000000000b1',
      layers: {
        L0: EMPTY_LAYER,
        L1: { nodes: [{ id: 'n1', type: 'USER', x: 0, y: 0, seq: 7 }], edges: [], boundaries: [], annotations: [] },
        L2: EMPTY_LAYER,
        L3: EMPTY_LAYER,
        PQC: EMPTY_LAYER,
      },
      activeLayer: 'L1',
      activeFramework: 'ALL',
      suppressions: { 't-1': { status: 'accepted', note: 'n', at: 1 } },
      findings: [FINDING],
      vulnIntel: { 'CVE-2026-0001': { epss: { score: 0.5 } } },
      idCounters: {
        L0: { node: 0, edge: 0, boundary: 0 },
        L1: { node: 9, edge: 0, boundary: 0 },
        L2: { node: 0, edge: 0, boundary: 0 },
        L3: { node: 0, edge: 0, boundary: 0 },
        PQC: { node: 0, edge: 0, boundary: 0 },
      },
    });
    const out = normalizeProject(JSON.parse(JSON.stringify(current)))!;
    expect(out.projectId).toBe('00000000-0000-4000-8000-0000000000b1');
    expect(out.suppressions).toEqual(current.suppressions);
    expect(out.vulnIntel).toEqual(current.vulnIntel);
    expect(out.updatedAt).toBe(current.updatedAt);
    // 既存の seq とカウンタは保つ（番号を再利用しない）
    expect(out.layers?.L1.nodes[0].seq).toBe(7);
    expect(out.idCounters?.L1.node).toBe(9);
    // 指摘は記録の内容を保ち、付加情報が付け直される
    expect(out.findings?.[0]).toMatchObject({ id: 'Example:f-1', externalId: 'f-1', epss: { score: 0.5 } });
  });
});
