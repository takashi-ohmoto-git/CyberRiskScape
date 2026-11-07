import { describe, expect, it } from 'vitest';
import type { BomComponent, DiagramNode, Finding } from '../../core/model/types';
import { sbomAcceptance } from './sbomAcceptance';

const node = (id: string, seq: number, type: string): DiagramNode => ({ id, seq, type, x: 0, y: 0, label: `n${seq}` }) as DiagramNode;
const layers = { L1: { nodes: [node('a', 1, 'FRONT_END_SERVER'), node('b', 2, 'FRONT_END_SERVER'), node('p', 3, 'PERSONAL_INFO')] } };
const now = new Date('2026-11-07T00:00:00Z');

const comp = (name: string, extra: Partial<BomComponent> = {}): BomComponent => ({
  id: `c:${name}`,
  source: { format: 'cyclonedx', product: 'vendor-sbom', scope: 'app1', importedAt: '2026-11-01T00:00:00Z' },
  externalId: name,
  identifiers: [],
  kind: 'software',
  name,
  version: '1.0.0',
  licenses: ['MIT'],
  ...extra,
});

const finding = (id: string, severity: Finding['severity'], extra: Partial<Finding> = {}): Finding => ({
  id,
  source: { format: 'cyclonedx', product: 'vendor-sbom', importedAt: 't' },
  externalId: id,
  identifiers: [],
  severity,
  canonicalIds: [],
  ...extra,
});

describe('sbomAcceptance', () => {
  it('patch 宣言の型で部品が結びついていないノード → nodesWithoutSbom（宣言の無い型は対象外）', () => {
    const r = sbomAcceptance({ layers, bomComponents: [comp('x', { subject: { layer: 'L1', nodeId: 'a' } })] }, { now });
    expect(r.nodesWithoutSbom).toEqual(['C2 n2']);
  });

  it('subject 無し・ノード消失の部品 → 製品 × scope でまとめ、名前は上限まで', () => {
    const r = sbomAcceptance(
      { layers, bomComponents: [comp('a'), comp('b'), comp('c', { subject: { layer: 'L1', nodeId: 'gone' } })] },
      { now, maxNames: 2 },
    );
    expect(r.unboundComponents).toEqual([{ product: 'vendor-sbom', scope: 'app1', count: 3, names: ['a@1.0.0', 'b@1.0.0'] }]);
  });

  it('作成時刻が maxAgeDays より古い → stale、時刻なし → noTimestamp、inventory は対象外', () => {
    const r = sbomAcceptance(
      {
        layers,
        bomComponents: [
          comp('old', { observedAt: '2026-01-01T00:00:00Z' }),
          comp('new', { observedAt: '2026-11-01T00:00:00Z', source: { format: 'spdx', product: 'p2', scope: 's', importedAt: 't' } }),
          comp('none', { source: { format: 'spdx', product: 'p3', importedAt: 't' } }),
          comp('inv', { source: { format: 'inventory', product: 'p4', importedAt: 't' } }),
        ],
      },
      { now },
    );
    const by = (p: string) => r.perSource.find((s) => s.product === p)!;
    expect(by('vendor-sbom')).toMatchObject({ stale: true, noTimestamp: false });
    expect(by('p2')).toMatchObject({ stale: false });
    expect(by('p3')).toMatchObject({ noTimestamp: true, stale: false });
    expect(r.perSource).toHaveLength(3);
    expect(sbomAcceptance({ layers, bomComponents: [comp('old', { observedAt: '2026-01-01T00:00:00Z' })] }, { now, maxAgeDays: 365 }).perSource[0].stale).toBe(false);
  });

  it('cyclonedx の指摘 → ノードごとに深刻度と KEV を数え、未結合は最後', () => {
    const sub = { layer: 'L1' as const, nodeId: 'a' };
    const r = sbomAcceptance(
      {
        layers,
        findings: [
          finding('f0', 'Low'),
          finding('f1', 'High', { subject: sub }),
          finding('f2', 'High', { subject: sub, kev: { dateAdded: '2099-01-01' } }),
          finding('f3', 'Low', { source: { format: 'sarif', product: 'x', importedAt: 't' }, subject: sub }),
        ],
      },
      { now },
    );
    expect(r.vulnerabilities.map((v) => v.node)).toEqual(['C1 n1', null]);
    expect(r.vulnerabilities[0]).toMatchObject({ total: 2, kev: 1, counts: { High: 2, Low: 0 } });
  });

  it('licenses が無い・空の部品 → licensesMissing に数える', () => {
    const r = sbomAcceptance({ layers, bomComponents: [comp('a'), comp('b', { licenses: [] }), comp('c', { licenses: undefined })] }, { now });
    expect(r.licensesMissing).toBe(2);
  });
});
