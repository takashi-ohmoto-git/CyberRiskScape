import { describe, expect, it } from 'vitest';
import { contextLookup, contextToMarkdown } from './context';
import { cveFinding, makeProject } from './__fixtures__/findingsPriorityProject';

/** 攻撃者 → 前段(rp) → 公開サーバー(web) → 業務 DB(mid) → 顧客情報(pii) の図に、資産・部品・指摘を載せる。 */
function project(opts: { attacker?: boolean } = {}): object {
  const base = makeProject(
    [
      cveFinding('f1', 'web', 'Medium', 'CVE-2099-0001', { kev: { dateAdded: '2099-01-01' } }),
      cveFinding('f2', 'mid', 'Low', 'CVE-2099-0002'),
    ],
    opts,
  ) as { layers: { L1: { nodes: object[]; edges: object[] } } };
  const l1 = base.layers.L1;
  return {
    ...base,
    layers: {
      ...base.layers,
      L1: {
        ...l1,
        nodes: [...l1.nodes, { id: 'rp', seq: 5, type: 'REVERSE_PROXY', x: 0, y: 0, label: '前段プロキシ' }],
        edges: [...l1.edges, { id: 'e3', source: 'rp', target: 'web', auth: 'MFA', network: 'VPC', encryption: 'TLS' }],
      },
    },
    assets: [
      {
        id: 'a1',
        source: { format: 'shodan', product: 'example-asm', importedAt: '2026-11-01T00:00:00Z' },
        kind: 'service',
        host: 'WWW.example.com',
        ip: '203.0.113.10',
        port: 443,
        subject: { layer: 'L1', nodeId: 'web' },
      },
      {
        id: 'a2',
        source: { format: 'shodan', product: 'example-asm', importedAt: '2026-11-01T00:00:00Z' },
        kind: 'service',
        host: 'orphan.example.com',
        ip: '203.0.113.99',
      },
    ],
    bomComponents: [
      {
        id: 'b1',
        source: { format: 'cyclonedx', product: 'example-sbom', importedAt: '2026-11-01T00:00:00Z' },
        externalId: 'pkg:npm/example-lib@1.2.3',
        identifiers: [{ scheme: 'purl', value: 'pkg:npm/example-lib@1.2.3' }],
        kind: 'software',
        name: 'example-lib',
        version: '1.2.3',
        subject: { layer: 'L1', nodeId: 'mid' },
      },
    ],
  };
}

describe('contextLookup', () => {
  it('ip：資産 → ノード・前段・脅威・指摘・露出を返す', () => {
    const r = contextLookup(project(), { ip: '203.0.113.10' });
    expect(r.matches).toHaveLength(1);
    const m = r.matches[0];
    expect(m.matchedBy).toBe('asset');
    expect(m.bound).toBe(true);
    expect(m.node).toMatchObject({ elementalId: 'C2', type: 'FRONT_END_SERVER' });
    expect(m.frontDoors?.map((f) => f.type)).toEqual(['REVERSE_PROXY']);
    expect(m.threats!.length).toBeGreaterThan(0);
    expect(m.findings).toHaveLength(1);
    expect(m.findings![0]).toMatchObject({ priority: 'P1', kev: true });
    expect(m.exposure?.value).toBe('entry');
    expect(m.exposure?.reachesTargets.length).toBeGreaterThan(0);
  });

  it('host：大文字小文字を区別せず資産に一致し、ノードのラベルにも一致する', () => {
    expect(contextLookup(project(), { host: 'www.EXAMPLE.com' }).matches[0].matchedBy).toBe('asset');
    const byLabel = contextLookup(project(), { host: '業務 db' });
    expect(byLabel.matches[0]).toMatchObject({ matchedBy: 'nodeLabel', bound: true });
    expect(byLabel.matches[0].exposure?.value).toBe('reachable');
  });

  it('purl：版つきは完全一致、版なしは版違いも含む。範囲外の版は一致しない', () => {
    expect(contextLookup(project(), { purl: 'pkg:npm/example-lib@1.2.3' }).matches).toHaveLength(1);
    expect(contextLookup(project(), { purl: 'pkg:npm/example-lib' }).matches).toHaveLength(1);
    expect(contextLookup(project(), { purl: 'pkg:npm/example-lib@9.9.9' }).matches).toHaveLength(0);
    const m = contextLookup(project(), { purl: 'pkg:npm/example-lib' }).matches[0];
    expect(m.node?.elementalId).toBe('C3');
    expect(m.findings?.[0].id).toBe('f2');
  });

  it('未結合の資産は bound:false。一致なしは空配列でエラーにしない', () => {
    const r = contextLookup(project(), { ip: '203.0.113.99' });
    expect(r.matches[0]).toMatchObject({ bound: false });
    expect(r.matches[0].note).toContain('未結合');
    expect(contextLookup(project(), { ip: '203.0.113.1' }).matches).toEqual([]);
  });

  it('攻撃者が図に無ければ露出は評価不可', () => {
    const r = contextLookup(project({ attacker: false }), { ip: '203.0.113.10' });
    expect(r.noAttacker).toBe(true);
    expect(r.matches[0].exposure?.value).toBe('unevaluated');
  });

  it('クエリは 1 つだけ。不正な --attacker は拒否する', () => {
    expect(() => contextLookup(project(), {})).toThrow('1 つだけ');
    expect(() => contextLookup(project(), { ip: '203.0.113.10', host: 'x' })).toThrow('1 つだけ');
    expect(() => contextLookup(project(), { ip: '203.0.113.10' }, { attacker: 'C9' })).toThrow('見つかりません');
  });

  it('md：注意書き・ノード・指摘の表を出し、悪用できるとは言わない', () => {
    const md = contextToMarkdown(contextLookup(project(), { ip: '203.0.113.10' }));
    expect(md).toContain('# 文脈の照会（ip=203.0.113.10）');
    expect(md).toContain('悪用できるとは言わない');
    expect(md).toContain('前段: C5 前段プロキシ（REVERSE_PROXY）');
    expect(md).toContain('| 指摘 | 製品 | 元の深刻度 | 推奨 |');
    expect(contextToMarkdown(contextLookup(project(), { ip: '203.0.113.1' }))).toContain('見つからなかった');
  });

  it('プロジェクトを書き換えない', () => {
    const p = project();
    const before = JSON.stringify(p);
    contextLookup(p, { ip: '203.0.113.10' });
    expect(JSON.stringify(p)).toBe(before);
  });
});
