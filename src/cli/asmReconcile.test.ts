import { describe, expect, it } from 'vitest';
import { asmReconcile, reconcileToJson, reconcileToMarkdown } from './asmReconcile';
import { makeProject } from './__fixtures__/findingsPriorityProject';

const asset = (ip: string, port: number, nodeId?: string) => ({
  id: `Shodan:s:${ip}:${port}`,
  source: { format: 'shodan', product: 'Shodan', scope: 's', importedAt: '2026-11-01T00:00:00Z' },
  externalId: `${ip}:${port}/tcp`,
  identifiers: [{ scheme: 'ip', value: ip }],
  kind: 'service',
  host: ip,
  ip,
  port,
  serviceName: 'https',
  observedAt: '2026-10-30T00:00:00Z',
  ...(nodeId ? { subject: { layer: 'L1', nodeId } } : {}),
});
const project = (assets: object[]) => ({ ...(makeProject([]) as object), assets });

describe('asmReconcile', () => {
  it('md：図に無い観測・Global IP 未入力の観測・公開と入力したが観測に無いノードを出す', () => {
    const md = reconcileToMarkdown(asmReconcile(project([asset('203.0.113.1', 443), asset('203.0.113.2', 22, 'mid')])));
    expect(md).toContain('## 図に無いのに外から見える（1 件）');
    expect(md).toContain('203.0.113.1');
    expect(md).toContain('## 外から見えている（Global IP が未入力）（1 件）');
    expect(md).toContain('C3 業務 DB');
    expect(md).toContain('L1: C2 公開サーバー');
  });

  it('観測が無い図 → ASM 結果が未取り込みと書く', () => {
    expect(reconcileToMarkdown(asmReconcile(project([])))).toContain('ASM 結果が未取り込み');
  });

  it('previous 指定 → json に diff を含める', () => {
    const j = reconcileToJson(asmReconcile(project([asset('203.0.113.1', 443)]), project([asset('203.0.113.9', 80)]))) as {
      kind: string;
      diff: { appeared: unknown[]; disappeared: unknown[] };
    };
    expect(j.kind).toBe('cyberriskscape-asm-reconcile');
    expect(j.diff.appeared).toHaveLength(1);
    expect(j.diff.disappeared).toHaveLength(1);
  });
});
