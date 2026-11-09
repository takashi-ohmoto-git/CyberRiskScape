import { beforeEach, describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { DfdListModal } from './DfdListModal';
import { useDiagramStore } from '../../core/state/diagramStore';
import type { DiagramEdge, DiagramNode } from '../../core/model/types';

function setup(open: boolean): void {
  const s = useDiagramStore.getState();
  const nodes: DiagramNode[] = [
    { id: 'n1', seq: 1, type: 'FRONT_END_SERVER', x: 0, y: 0, label: 'Frontend', description: '公開サイト' },
    { id: 'n2', seq: 2, type: 'DATABASE', x: 200, y: 0, label: 'MainDB' },
  ];
  const edges: DiagramEdge[] = [
    {
      id: 'e1',
      seq: 1,
      source: 'n1',
      target: 'n2',
      auth: 'None',
      network: 'VPC',
      encryption: 'TLS',
      protocol: 'db_sql',
      description: '注文データ',
    },
  ];
  const patch = {
    layers: { ...s.layers, [s.activeLayer]: { ...s.layers[s.activeLayer], nodes, edges, boundaries: [] } },
    isDfdListOpen: open,
  };
  useDiagramStore.setState(patch);
  // renderToStaticMarkup は zustand の初期状態（getServerSnapshot）を読むため、そちらにも反映する。
  Object.assign(useDiagramStore.getInitialState(), patch);
}

describe('DfdListModal', () => {
  beforeEach(() => setup(false));

  it('閉じているとき → 何も描画しない', () => {
    expect(renderToStaticMarkup(<DfdListModal />)).toBe('');
  });

  it('開いているとき → 件数つきタブと構成要素の行を出す', () => {
    setup(true);
    const html = renderToStaticMarkup(<DfdListModal />);
    expect(html).toContain('role="dialog"');
    expect(html).toContain('構成要素（2）');
    expect(html).toContain('データフロー（1）');
    expect(html).toContain('Frontend');
    expect(html).toContain('MainDB');
    expect(html).toContain('公開サイト');
    // 説明は備考扱いで右端の列
    const headers = [...html.matchAll(/<th[^>]*>([^<]*)<\/th>/g)].map((m) => m[1]);
    expect(headers).toEqual(['ID', '種別', '名称', '所属（境界・親）', '内包', '説明']);
  });
});
