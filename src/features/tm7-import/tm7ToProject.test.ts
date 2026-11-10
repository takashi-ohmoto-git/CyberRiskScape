import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyzeProject } from '../../cli/analyze';
import { deserializeProject } from '../persistence/serialize';
import { tm7ToProject, type Tm7ImportResult } from './tm7ToProject';

const XML = readFileSync(new URL('./__fixtures__/example.tm7', import.meta.url), 'utf8');
const NOW = 1_700_000_000_000;

const ok = (r: Tm7ImportResult) => {
  if (!r.ok) throw new Error(r.error);
  return r;
};
const imported = () => ok(tm7ToProject(XML, { now: NOW }));
const L1 = () => imported().project.layers!.L1;
const node = (label: string) => L1().nodes.find((n) => n.label === label)!;
const edge = (name: string) => L1().edges.find((e) => e.dataFlowName === name)!;

describe('tm7ToProject', () => {
  it('要素: 対応表の型に寄せ、元の型と選んだ属性を説明に残す（既定の選択のままの属性は残さない）', () => {
    expect(node('Customer').type).toBe('USER');
    expect(node('Order Portal').type).toBe('FRONT_END_SERVER');
    expect(node('Orders DB').type).toBe('DATABASE');
    const desc = node('Order Portal').description!;
    expect(desc).toContain('SE.P.TMCore.WebApp');
    expect(desc).toContain('Running As = Administrator');
    expect(desc).not.toContain('Sanitizes Input');
  });

  it('要素: 対象外（Out Of Scope）とその理由を説明に残す', () => {
    expect(node('Orders DB').description).toContain('Managed by the platform team');
  });

  it('要素: 対応表に無いテンプレートの型は親の汎用型で取り込み、要確認にする', () => {
    const n = node('Batch Job');
    expect(n.type).toBe('PROCESS');
    expect(n.description).toContain('SE.P.Azure.ExampleFunction');
    expect(imported().summary.review).toContainEqual({ layer: 'L1', label: 'Batch Job', reason: 'unmappedType' });
  });

  it('線: 向き・暗号（Provides Confidentiality）・認証・プロトコル・名前を写す', () => {
    const e = edge('Place order');
    expect(e.source).toBe(node('Customer').id);
    expect(e.target).toBe(node('Order Portal').id);
    expect(e.dataFlow).toBe('outbound');
    expect(e.encryption).toBe('TLS');
    expect(e.auth).toBe('Password');
    expect(e.protocol).toBe('http_rest');
    expect(edge('Write order').encryption).toBe('Plain');
    expect(edge('Write order').auth).toBe('None');
  });

  it('線: 両端が同じ枠の境界の中なら VPC、そうでなければ Internet', () => {
    expect(edge('Write order').network).toBe('VPC');
    expect(edge('Place order').network).toBe('Internet');
  });

  it('枠の形の境界: CorpNet は社内のマクロセグメントにする', () => {
    const b = L1().boundaries[0];
    expect(b).toMatchObject({ type: 'ROUNDED', macroTrust: 'Office Area', trustLevel: 'Internal', label: 'Corp Network' });
  });

  it('線の形の境界・つながっていない線は、座標つきの注釈として残し要確認にする', () => {
    const texts = (L1().annotations ?? []).map((a) => a.text);
    expect(texts.some((t) => t.includes('Internet Boundary') && t.includes('(200, 0)'))).toBe(true);
    expect(texts.some((t) => t.includes('Loose flow'))).toBe(true);
    const reasons = imported().summary.review.map((r) => r.reason);
    expect(reasons).toContain('lineBoundary');
    expect(reasons).toContain('danglingFlow');
  });

  it('メモ: 追加した人・日時ごと注釈に残す', () => {
    const texts = (L1().annotations ?? []).map((a) => a.text);
    expect(texts.some((t) => t.includes('Check the batch job owner') && t.includes('EXAMPLE\\carol'))).toBe(true);
  });

  it('モデル情報: 名前・説明・責任者・レビュー担当・関係者・前提条件・外部依存を写す', () => {
    expect(imported().project.projectMeta).toMatchObject({
      name: 'Example Orders',
      purpose: 'Fictional order system',
      owner: 'Erin',
      reviewer: 'Frank',
      contributors: 'Carol, Dave',
      assumptions: 'Users sign in through the corporate IdP',
      externalDependencies: 'Payment service',
    });
  });

  it('脅威: 手動脅威として線に紐づけ、元の項目を importedFrom にそのまま残す', () => {
    const threats = imported().project.manualThreats!.L1;
    expect(threats).toHaveLength(3);
    const t1 = threats.find((t) => t.id === 'tm7-1')!;
    expect(t1).toMatchObject({
      framework: 'STRIDE',
      category: 'Spoofing the Customer External Entity',
      severity: 'High',
      subject: { kind: 'edge', id: edge('Place order').id },
      nodeId: node('Order Portal').id,
    });
    expect(t1.importedFrom?.fields).toMatchObject({ TypeId: 'S3', State: 'Mitigated', ChangedBy: 'EXAMPLE\\alice' });
  });

  it('脅威の状態: Mitigated→実装済み・NeedsInvestigation→要対応、理由・変更者・日時を残す。未着手は状況なし', () => {
    const cs = imported().project.controlStatuses!;
    expect(cs['tm7-1']).toEqual({
      status: 'implemented',
      note: 'Sign-in uses the corporate IdP',
      at: Date.parse('2026-01-02T03:04:05+09:00'),
      by: 'EXAMPLE\\alice',
    });
    expect(cs['tm7-2']).toMatchObject({ status: 'required', by: 'EXAMPLE\\bob' });
    expect(cs['tm7-3']).toBeUndefined();
  });

  it('出力は保存形式のスキーマに適合する', () => {
    expect(deserializeProject(JSON.parse(JSON.stringify(imported().project)))).not.toBeNull();
  });

  it('取り込んだ図で CyberRiskScape の脅威が検出され、取り込んだ TMT の脅威も並ぶ', () => {
    const threats = analyzeProject(imported().project).flatMap((l) => l.threats);
    expect(threats.some((t) => t.origin === 'detected')).toBe(true);
    expect(threats.filter((t) => t.origin === 'manual')).toHaveLength(3);
    const mitigated = threats.find((t) => t.id === 'tm7-1');
    expect(mitigated?.controlStatus?.status).toBe('implemented');
  });

  it.each([
    ['XML でないもの', 'not xml <<<', false],
    ['別の XML', '<root><x/></root>', false],
  ])('不正な入力（%s）はエラーを返す', (_label, text) => {
    expect(tm7ToProject(text).ok).toBe(false);
  });
});
