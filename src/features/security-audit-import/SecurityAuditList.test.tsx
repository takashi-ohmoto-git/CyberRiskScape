import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import type { Finding, LayerData } from '../../core/model/types';
import { buildAuditRows } from './auditRows';
import { translate, type TranslationKey } from '../../i18n';
import { SecurityAuditList, factText } from './SecurityAuditList';
import { SecurityAuditMarks } from './SecurityAuditMarks';

const LAYER: LayerData = {
  nodes: [{ id: 'n1', seq: 1, type: 'BACKEND_API', x: 0, y: 0 }],
  edges: [],
  boundaries: [],
  annotations: [],
} as unknown as LayerData;

function f(over: Partial<Finding>): Finding {
  return {
    id: 'a',
    source: { product: 'x', format: 'security-audit' },
    externalId: 'a',
    identifiers: [],
    title: 'Order lookup issue',
    severity: 'High',
    canonicalIds: ['idor'],
    subject: { layer: 'L1', nodeId: 'n1' },
    resource: { label: 'src/api/orders.ts:42' },
    conditions: [{ kind: 'reachability', text: 'Reachable from the internet.' }],
    ...over,
  } as Finding;
}

const html = (findings: Finding[], defaultOpen = false) =>
  renderToStaticMarkup(<SecurityAuditList rows={buildAuditRows(findings, 'n1', LAYER)} defaultOpen={defaultOpen} />);

describe('SecurityAuditList', () => {
  it('実証は「実証（ローカル）」と重大度を出す', () => {
    const out = html([f({})]);
    expect(out).toContain('実証（ローカル）');
    expect(out).toContain('High');
    expect(out).toContain('src/api/orders.ts:42');
    expect(out).toContain('脅威カードに対応づけあり');
  });

  it('要確認は「要確認・重大度なし」で、重大度の語を出さない', () => {
    const out = html([f({ outcome: 'unverified', severity: 'Low', canonicalIds: [], openQuestions: ['Is flag on?'] })], true);
    expect(out).toContain('要確認・重大度なし');
    expect(out).not.toContain('Low');
    expect(out).not.toContain('実証（ローカル）');
    expect(out).toContain('脅威カードに対応づけなし');
    expect(out).toContain('Is flag on?');
  });

  it('展開すると前提の文と図の事実を並べ、判定語は出さない', () => {
    const out = html([f({})], true);
    expect(out).toContain('Reachable from the internet.');
    expect(out).toContain('このノードの信頼境界：Internet');
    expect(out).toContain('このノードへデータが入る接続がありません。');
    expect(out).not.toContain('成立する');
    expect(out).not.toContain('成立しない');
    expect(out).not.toContain('正しい');
  });

  it('閉じていると詳細は出さない', () => {
    expect(html([f({})])).not.toContain('Reachable from the internet.');
  });

  it('指摘が無いときは空表示', () => {
    expect(html([])).toContain('ソース監査の指摘はありません');
  });
});

describe('SecurityAuditMarks', () => {
  it('実証と要確認の印を別々に出す', () => {
    expect(renderToStaticMarkup(<SecurityAuditMarks confirmed unverified={false} />)).toContain('ソース監査で実証（ローカル）');
    const u = renderToStaticMarkup(<SecurityAuditMarks confirmed={false} unverified />);
    expect(u).toContain('ソース監査で要確認');
    expect(u).not.toContain('実証');
    expect(renderToStaticMarkup(<SecurityAuditMarks confirmed={false} unverified={false} />)).toBe('');
  });
});

describe('factText', () => {
  it('接続の認証・経路は既存の表示名に引き直す', () => {
    const t = (key: TranslationKey, params?: Record<string, string | number>) => translate(key, 'ja', params);
    expect(factText(t, { key: 'authentication.edgeAuth', params: { auth: 'ApiKey', count: 2 } })).toContain('APIキー');
    expect(factText(t, { key: 'reachability.edgeNetwork', params: { network: 'VPC', count: 1 } })).toContain('閉域網');
  });
});
