import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { buildRoe, type RoeInput } from './buildRoe';
import { roeToJson, roeToMarkdown } from './roeOutput';
import { analyzeProject } from '../../cli/analyze';
import type { Asset } from '../../core/model/types';

const NOW = new Date('2026-10-20T12:00:00Z'); // generatedAt は実行環境の日付

function sampleInput(): RoeInput {
  const raw = JSON.parse(readFileSync('src/cli/__fixtures__/sample-project.json', 'utf-8'));
  return analyzeProject(raw)[0].input;
}

describe('buildRoe (sample-project)', () => {
  it('generatedAt を実行環境の日付で作る', () => {
    const doc = buildRoe(sampleInput(), NOW, 'ja');
    expect(doc.generatedAt).toBe('2026-10-20');
    expect(doc.product).toBeTruthy();
  });

  it('境界が無いノードは外部に倒さず in-scope（未宣言・要確認）に入れる', () => {
    const input = sampleInput(); // sample-project には信頼境界が無い
    const doc = buildRoe(input, NOW, 'ja');
    // 自社資産が全部スコープ外になる退行を防ぐ：境界未描画でも in-scope に入る
    expect(doc.inScope.length).toBeGreaterThan(0);
    for (const e of doc.inScope) {
      expect(['Internal', 'Undeclared']).toContain(e.zone);
      if (e.zone === 'Undeclared') expect(e.reason).toBe('undeclared');
      else expect(e.reason).toBe('');
    }
    for (const e of doc.outOfScope) {
      expect(['thirdParty', 'partnerZone', 'internetZone']).toContain(e.reason);
    }
    // in-scope と out-of-scope の id は重複しない
    const ids = new Set([...doc.inScope, ...doc.outOfScope].map((e) => e.id));
    expect(ids.size).toBe(doc.inScope.length + doc.outOfScope.length);
  });

  it('Internet 境界に置いたノードは out-of-scope になる', () => {
    const input = sampleInput();
    const first = input.nodes.find((n) => n.parentId == null);
    expect(first).toBeDefined();
    // first ノードを丸ごと覆う Internet 境界を足す
    input.boundaries = [
      ...input.boundaries,
      {
        id: 'b-internet',
        type: 'RECT',
        x: first!.x - 500,
        y: first!.y - 500,
        width: 1000,
        height: 1000,
        trustLevel: 'Internet',
      },
    ];
    const doc = buildRoe(input, NOW, 'ja');
    const moved = doc.outOfScope.find((e) => e.name === first!.label || e.type === first!.type);
    expect(moved?.reason).toBe('internetZone');
  });

  it('承認方針は 6 項目を出す', () => {
    const doc = buildRoe(sampleInput(), NOW, 'ja');
    expect(doc.approvalPolicy.length).toBe(6);
  });

  it('Markdown に主要な見出しと「図に無いものはスコープ外」の明記が出る', () => {
    const md = roeToMarkdown(buildRoe(sampleInput(), NOW, 'ja'));
    expect(md).toContain('# 交戦規定（RoE）／スコープ宣言');
    expect(md).toContain('許可された対象');
    expect(md).toContain('スコープ外');
    expect(md).toContain('描かれていない対象は、すべてスコープ外');
    // 未解決の翻訳キー（roe.* / approval.*）が素のまま漏れていない
    expect(md).not.toMatch(/\broe\.[a-zA-Z.]+/);
    expect(md).not.toMatch(/\bapproval\.[a-zA-Z]+/);
  });

  it('英語でも見出しが英語になり、翻訳キーが漏れない', () => {
    const md = roeToMarkdown(buildRoe(sampleInput(), NOW, 'en'));
    expect(md).toContain('# Rules of engagement');
    expect(md).toContain('Authorized targets');
    expect(md).not.toMatch(/\broe\.[a-zA-Z.]+/);
    expect(md).not.toMatch(/\bapproval\.[a-zA-Z]+/);
  });

  it('JSON は RoeDocument をそのまま出す', () => {
    const doc = buildRoe(sampleInput(), NOW, 'ja');
    const parsed = JSON.parse(roeToJson(doc));
    expect(parsed.inScope.length).toBe(doc.inScope.length);
    expect(parsed.approvalPolicy.length).toBe(6);
  });
});

describe('buildRoe アドレスの手がかり（資産優先）', () => {
  const asset = (id: string, nodeId: string, over: Partial<Asset> = {}): Asset => ({
    id,
    source: { format: 'manual', product: 'Manual', importedAt: '2026-11-08T00:00:00Z' },
    externalId: id,
    identifiers: [],
    kind: 'service',
    host: 'staging.example.com',
    subject: { layer: 'L1', nodeId },
    ...over,
  });

  /**
   * sample-project の最初の in-scope ノードにラベルの手がかりを付け、`makeAssets(そのノードの id)` の資産で RoE を作る。
   * 資産は必ず対象ノードに付くので、条件分岐なしで検証できる。
   */
  function roeFor(makeAssets: (nodeId: string) => Asset[], label = 'Web（old.example.com）') {
    const input = sampleInput();
    expect(input.layer).toBe('L1');
    const targetId = buildRoe(input, NOW, 'ja').inScope[0].id;
    const node = input.nodes.find((n) => (n.seq != null ? `C${n.seq}` : n.id) === targetId);
    expect(node).toBeDefined();
    node!.label = label;
    const doc = buildRoe({ ...input, assets: makeAssets(node!.id) }, NOW, 'ja');
    return { doc, entry: doc.inScope.find((e) => e.id === targetId)! };
  }

  it('ノードに結びついた資産がある → host・ip・url を重複なしで全部出し、出どころは asset（ラベルより優先）', () => {
    const { entry } = roeFor((id) => [
      asset('a1', id, { ip: '203.0.113.10', port: 443 }),
      asset('a2', id, { ip: '203.0.113.10', port: 80 }),
      asset('a3', id, { kind: 'endpoint', url: 'https://staging.example.com/api/v1/runs' }),
    ]);
    expect(entry).toMatchObject({
      addressHint: 'staging.example.com, 203.0.113.10, https://staging.example.com/api/v1/runs',
      addressSource: 'asset',
    });
  });

  it('資産が他ノード・他レイヤーのものだけ → 使わず、従来どおりラベルから拾う（出どころは text）', () => {
    const { entry } = roeFor((id) => [
      asset('x1', 'other-node', { ip: '203.0.113.99' }),
      { ...asset('x2', id), subject: { layer: 'L2', nodeId: id } },
    ]);
    expect(entry).toMatchObject({ addressHint: 'old.example.com', addressSource: 'text' });
  });

  it('資産もラベルの手がかりも無い → 空で、出どころも空', () => {
    const { entry } = roeFor(() => [], 'Web サーバー');
    expect(entry).toMatchObject({ addressHint: '', addressSource: '' });
  });

  it('Markdown は出どころで文言を分ける（資産＝登録した資産、ラベル＝手がかり。どちらも要確認）', () => {
    const viaAsset = roeToMarkdown(roeFor((id) => [asset('m1', id, { ip: '203.0.113.10' })]).doc);
    expect(viaAsset).toContain('アドレス（ノードに登録した資産）: staging.example.com, 203.0.113.10（要確認）');
    const viaText = roeToMarkdown(roeFor(() => []).doc);
    expect(viaText).toContain('アドレスの手がかり: old.example.com（要確認）');
  });

  it('英語でも資産の文言が翻訳される', () => {
    const { doc } = roeFor((id) => [asset('m1', id)]);
    const en = roeToMarkdown(buildRoe({ ...sampleInput(), assets: [] }, NOW, 'en'));
    expect(en).not.toContain('roe.addressAsset');
    expect(roeToMarkdown({ ...doc, locale: 'en' })).toContain('address (assets registered on the node): staging.example.com (confirm)');
  });
});

