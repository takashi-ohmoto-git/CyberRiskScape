import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { buildRoe, type RoeInput } from './buildRoe';
import { roeToJson, roeToMarkdown } from './roeOutput';
import { analyzeProject } from '../../cli/analyze';

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
