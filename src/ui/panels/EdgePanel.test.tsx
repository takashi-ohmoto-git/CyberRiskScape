import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { EdgePanel } from './EdgePanel';
import { EDGE_PROTOCOL_GROUPS, EDGE_PROTOCOLS, type DiagramEdge } from '../../core/model/types';
import { enPanels } from '../../i18n/locales/en/panels';

function edge(extra: Partial<DiagramEdge> = {}): DiagramEdge {
  return { id: 'e1', source: 'n1', target: 'n2', auth: 'None', network: 'VPC', encryption: 'TLS', ...extra };
}

describe('EdgePanel', () => {
  it('protocol：分類ごとの見出しつきで全選択肢を出し、設定値を選択状態にする', () => {
    const html = renderToStaticMarkup(<EdgePanel edge={edge({ protocol: 'db_sql' })} />);
    expect(html.match(/<optgroup /g)?.length).toBe(EDGE_PROTOCOL_GROUPS.length);
    for (const p of EDGE_PROTOCOLS) expect(html).toContain(`value="${p}"`);
    expect(html).toContain('<option value="db_sql" selected="">');
  });

  it('表示名・説明：見出しを i18n で出し、説明の値を入力欄に出す', () => {
    const html = renderToStaticMarkup(<EdgePanel edge={edge({ description: '同期・要求／応答' })} />);
    expect(html).not.toContain('Data Flow Name');
    expect(html).toContain('表示名（データフロー名）');
    expect(html).toMatch(/<textarea id="edge-desc-e1"[^>]*>同期・要求／応答<\/textarea>/);
  });

  it('protocol：英語の文言が全分類・全選択肢にある（en の欠落は型で検出されないため）', () => {
    for (const g of EDGE_PROTOCOL_GROUPS) {
      expect(enPanels[`panels.edge.protocolGroup.${g.group}`], g.group).toBeTruthy();
    }
    for (const p of EDGE_PROTOCOLS) expect(enPanels[`panels.edge.protocol.${p}`], p).toBeTruthy();
  });
});
