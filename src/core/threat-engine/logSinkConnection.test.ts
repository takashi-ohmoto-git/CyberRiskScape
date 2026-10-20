import { describe, expect, it } from 'vitest';
import { detectThreats } from './detectThreats';
import { renderNodeTemplate } from './renderTemplate';
import { buildLogSinkClosure, isReferencedLogSink, logSourcesOf } from './logSinkClosure';
import type { DiagramEdge, DiagramNode } from '../model/types';
import type { ThreatRule } from '../../threat-library/schema/threatRule';

/**
 * 送信先（logSinkId）として参照された SIEM を「論理的に接続されている」とみなす挙動。
 * authProviderId の論理接続（logicalConnection.test.ts）と同じ規則。
 */
const siem: DiagramNode = { id: 'siem', type: 'SIEM', x: 0, y: 0, label: 'Sentinel' };
const pc: DiagramNode = { id: 'pc', type: 'PC', x: 100, y: 0, label: 'PC-A', logSinkId: 'siem' };
const srv: DiagramNode = { id: 'srv', type: 'PROCESS', x: 200, y: 0, label: 'App', logSinkId: 'siem' };

function rule(extra?: Record<string, unknown>): ThreatRule {
  return {
    id: 'siem-rule',
    framework: 'STRIDE',
    category: 'Denial of Service',
    severity: 'Medium',
    description: 'siem rule',
    appliesTo: { kind: 'node', nodeType: 'SIEM', ...extra },
  } as ThreatRule;
}

function fired(nodes: DiagramNode[], edges: DiagramEdge[], r: ThreatRule): string[] {
  return detectThreats({ nodes, edges, framework: 'STRIDE', rules: [r] }).map((t) => t.nodeId);
}

describe('logSinkId による論理接続', () => {
  it('参照だけで素の接続要件を満たす（エッジが無くても発火）', () => {
    expect(fired([siem, pc], [], rule())).toEqual(['siem']);
  });

  it('参照もエッジも無い SIEM は発火しない', () => {
    const plain: DiagramNode = { ...pc, logSinkId: undefined };
    expect(fired([siem, plain], [], rule())).toEqual([]);
  });

  it('direction を指定したルールは参照では満たされない', () => {
    const r = rule({ connection: { required: true, direction: 'inbound' } });
    expect(fired([siem, pc], [], r)).toEqual([]);
  });

  it('peerType を指定したルールも参照では満たされない', () => {
    const r = rule({ connection: { required: true, peerType: ['PC'] } });
    expect(fired([siem, pc], [], r)).toEqual([]);
  });

  it('required:false は参照の有無によらず常に発火する（不変）', () => {
    const r = rule({ connection: { required: false } });
    expect(fired([siem], [], r)).toEqual(['siem']);
    expect(fired([siem, pc], [], r)).toEqual(['siem']);
  });

  it('参照先が存在しない・自己参照の logSinkId は数えない', () => {
    const dangling: DiagramNode = { ...pc, logSinkId: 'gone' };
    const self: DiagramNode = { ...siem, logSinkId: 'siem' };
    expect(fired([siem, dangling], [], rule())).toEqual([]);
    expect(fired([self], [], rule())).toEqual([]);
  });
});

describe('logSinkClosure', () => {
  it('送り元の一覧と参照の有無を返す', () => {
    const c = buildLogSinkClosure([siem, pc, srv]);
    expect(logSourcesOf(c, 'siem').map((n) => n.id)).toEqual(['pc', 'srv']);
    expect(isReferencedLogSink(c, 'siem')).toBe(true);
    expect(isReferencedLogSink(c, 'pc')).toBe(false);
    expect(logSourcesOf(c, 'pc')).toEqual([]);
  });
});

describe('{{logSourceCount}} / {{logSourceNames}}', () => {
  it('送り元の件数と名前を展開する', () => {
    const out = renderNodeTemplate('{{logSourceCount}} 件（{{logSourceNames}}）', siem, [], [pc, srv]);
    expect(out).toBe('2 件（PC-A、App）');
  });

  it('0 件でも文が壊れない（0 と明示的な語）', () => {
    expect(renderNodeTemplate('{{logSourceCount}} 件（{{logSourceNames}}）', siem, [], [])).toBe(
      '0 件（図で未指定）',
    );
    expect(renderNodeTemplate('{{logSourceCount}}', siem)).toBe('0');
  });

  it('既存の dependent トークンは変わらない', () => {
    expect(renderNodeTemplate('{{dependentCount}}', siem, [pc], [srv])).toBe('1');
  });

  it('detectThreats が説明文に送り元を展開する', () => {
    const r = { ...rule(), description: '送り元: {{logSourceNames}}' } as ThreatRule;
    const [t] = detectThreats({ nodes: [siem, pc, srv], edges: [], framework: 'STRIDE', rules: [r] });
    expect(t.description).toBe('送り元: PC-A、App');
  });
});
