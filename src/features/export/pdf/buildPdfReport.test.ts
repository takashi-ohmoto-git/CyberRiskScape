import fs from 'node:fs';
import path from 'node:path';
import { PDFDocument } from 'pdf-lib';
import { describe, expect, it } from 'vitest';
import { buildPdfReport, type PdfReportLayer } from './buildPdfReport';
import { createFontSubsetter } from './fontSubset';
import { buildThreatReport } from '../threatReport';
import {
  EMPTY_PROJECT_META,
  type ControlStatusValue,
  type DiagramNode,
  type LayerKey,
  type SuppressionStatus,
  type ThreatView,
} from '../../../core/model/types';

const root = path.resolve(__dirname, '../../../..');
const wasm = fs.readFileSync(path.join(root, 'node_modules/harfbuzzjs/dist/harfbuzz-subset.wasm'));
const regular = fs.readFileSync(path.join(root, 'src/assets/fonts/BIZUDPGothic-Regular.ttf'));
const bold = fs.readFileSync(path.join(root, 'src/assets/fonts/BIZUDPGothic-Bold.ttf'));

const NODES: DiagramNode[] = [{ id: 'n1', seq: 1, type: 'LLM', x: 0, y: 0, label: '与信審査用の大規模言語モデル' }];
const SEVS = ['Low', 'Medium', 'High', 'Critical'] as const;
const SUPPRESSIONS: (SuppressionStatus | undefined)[] = [
  undefined,
  'reduce',
  undefined,
  'accepted',
  'false-positive',
  'avoid',
  'transfer',
];
const CONTROLS: (ControlStatusValue | undefined)[] = [
  'implemented',
  undefined,
  'required',
  'not-applicable',
  'rejected',
  undefined,
];

/** 対策実装状況・リスク評価・対応方針・tier 付き緩和策が混ざった脅威。名前は長くして 2 行に折り返させる。 */
function threats(count: number): ThreatView[] {
  return Array.from({ length: count }, (_, i) => {
    const suppression = SUPPRESSIONS[i % SUPPRESSIONS.length];
    const control = CONTROLS[i % CONTROLS.length];
    const tiered = i % 2 === 0;
    return {
      id: `rule-${i}-n1`,
      ruleId: `rule-${i}`,
      subject: { kind: 'node', id: 'n1' },
      nodeId: 'n1',
      framework: 'AgenticAI',
      category: `カテゴリ${i}`,
      name: `共有コンテキストの汚染によるマルチテナント間の情報漏えいと権限昇格 ${i}（peer-agent feedback）`,
      severity: SEVS[i % 4],
      description:
        'マルチテナント環境で、攻撃者が共有メモリへ悪意ある指示を書き込み、他のエージェントがそれを信頼して実行してしまう。'.repeat(3),
      mitigation: tiered
        ? '[Foundation] 入力を検証する。 [Enterprise] 分類器で検査する。 [Advanced] 来歴を記録する。'
        : '入力の検証とサンドボックス化を行い、メモリの書き込み権限をテナント単位で分離する。'.repeat(2),
      mitigationTiers: tiered
        ? {
            foundation: '[Foundation] 書き込み経路の入力を検証し、信頼できない由来のデータはサニタイズするまで永続化しない。',
            enterprise: '[Enterprise] 書き込み前に分類器でスクリーニングし、疑わしいものは隔離キューへ回して人手でレビューする。',
            advanced: '[Advanced] 来歴チェーンを記録し、汚染源を特定して該当レコードのみロールバックできるようにする。',
          }
        : undefined,
      complianceRefs: i % 2 === 0 ? [{ standard: 'nist-ai-rmf', ref: 'GOVERN 1.1' }] : undefined,
      origin: 'detected',
      risk:
        i % 3 === 0
          ? { damage: ((i % 3) + 1) as 1 | 2 | 3, affectedUsers: 3, reproducibility: 2, exploitability: 3, at: 0 }
          : undefined,
      suppression: suppression ? { status: suppression, note: '理由を記録', at: 0 } : undefined,
      controlStatus: control ? { status: control, note: '補足', at: 0 } : undefined,
    } as ThreatView;
  });
}

function layer(key: LayerKey, count: number): PdfReportLayer {
  const ts = threats(count);
  return {
    layer: key,
    threats: ts,
    report: buildThreatReport({
      threats: ts,
      nodes: NODES,
      edges: [],
      boundaries: [],
      projectMeta: {
        ...EMPTY_PROJECT_META,
        name: 'ProjectIT',
        systemName: 'CreditScoringAPI',
        purpose: '与信審査を自動化する。',
        businessImpact: '停止すると審査が止まり、売上機会を失う。',
        securityObjectives: '顧客データの機密性を守る。\n審査結果の完全性を守る。',
      },
      framework: 'ALL',
      layer: key,
    }),
  };
}

function input(reports: PdfReportLayer[], locale: 'ja' | 'en' = 'ja') {
  return {
    reports,
    locale,
    generatedAt: new Date(2026, 9, 3, 12, 0),
    appVersion: '0.2.0',
    fonts: { regular, bold },
    harfbuzzWasm: wasm,
  };
}

/** pdfjs-dist（devDependency）でページ別テキストを取り出す。 */
async function pageTexts(bytes: Uint8Array): Promise<string[]> {
  const pdfjs = await import('pdfjs-dist/legacy/build/pdf.mjs');
  const doc = await pdfjs.getDocument({ data: bytes.slice() }).promise;
  const out: string[] = [];
  for (let i = 1; i <= doc.numPages; i++) {
    const content = await (await doc.getPage(i)).getTextContent();
    out.push(content.items.map((it) => ('str' in it ? it.str : '')).join(' '));
  }
  return out;
}

describe('subset', () => {
  it('使用文字だけに間引いてフォントが大幅に小さくなる', async () => {
    const s = await createFontSubsetter(wasm);
    const out = s.subset(regular, '脅威モデリング');
    expect(out.byteLength).toBeLessThan(regular.byteLength / 20);
  });
});

describe('buildPdfReport', () => {
  it('複数ページの PDF を小さいサイズで生成する', async () => {
    const bytes = await buildPdfReport(input([layer('L0', 3), layer('L1', 15)]));
    expect(new TextDecoder().decode(bytes.slice(0, 4))).toBe('%PDF');
    expect(bytes.byteLength).toBeLessThan(500 * 1024);
    const doc = await PDFDocument.load(bytes);
    expect(doc.getPageCount()).toBeGreaterThanOrEqual(2);
  });

  it('英語ロケールでも生成でき、脅威 0 件のレイヤーも扱える', async () => {
    const bytes = await buildPdfReport(input([layer('L0', 0)], 'en'));
    expect(new TextDecoder().decode(bytes.slice(0, 4))).toBe('%PDF');
  });

  it('最悪ケース（4 レイヤー・上位 10 件が長い名前）でも 1 ページ目が 1 ページに収まり、生の tier タグを印字しない', async () => {
    const bytes = await buildPdfReport(
      input([layer('L0', 14), layer('L1', 14), layer('L2', 14), layer('L3', 14)]),
    );
    const pages = await pageTexts(bytes);
    expect(pages[0]).toContain('合計'); // 1 ページ目の最後（レイヤー表の合計行）
    expect(pages[0]).not.toContain('評価の前提');
    expect(pages[1]).toContain('評価の前提');
    expect(pages.join(' ')).not.toMatch(/\[(Foundation|Enterprise|Advanced)\]/);
  }, 30_000);

  it('fi 合字を使わず、テキスト抽出で "fi" が欠けない', async () => {
    const l = layer('L0', 1);
    const row = l.report.rows[0];
    if (row) row.threat = 'The confidentiality of data must survive verification.';
    const pages = await pageTexts(await buildPdfReport(input([l], 'en')));
    const text = pages.join(' ').replace(/\s+/g, '');
    expect(text).toContain('confidentiality');
    expect(text).toContain('verification');
  }, 30_000);

  it('未入力の仮定：脅威名に * を付け、凡例・詳細の仮定項目・1 ページ目の件数・評価の前提の説明を出す', async () => {
    const l = layer('L0', 2);
    l.threats[0].assumptionFlags = ['posture', 'attackSurface'];
    const pages = await pageTexts(await buildPdfReport(input([l])));
    const text = pages.join(' ').replace(/\s+/g, '');
    expect(pages[0].replace(/\s+/g, '')).toContain('うち未入力の仮定1件');
    expect(text).toContain('*共有コンテキストの汚染');
    expect(text).toContain('*印：属性が未入力のため');
    expect(text).toContain('未入力の仮定運用状況・攻撃面属性');
    expect(text).toContain('未入力の扱い');
  }, 30_000);

  it('構成要素一覧・データフロー一覧：layerData があれば付録に DFD LIST と同じ列で出す（日英）', async () => {
    const l = layer('L0', 1);
    l.layerData = {
      nodes: [
        { id: 'n1', seq: 1, type: 'BACKEND_API', x: 0, y: 0, label: 'P3 ユーザー登録', description: '管理主体：アプリ管理者' },
        { id: 'n2', seq: 2, type: 'DATABASE', x: 300, y: 0, label: 'D1 ユーザーDB' },
      ],
      edges: [
        {
          id: 'e1', seq: 4, source: 'n1', target: 'n2', auth: 'Password', network: 'VPC', encryption: 'TLS',
          dataFlowName: 'F4 登録データ', protocol: 'db_sql', description: '同期・書込み',
        },
      ],
      boundaries: [],
      annotations: [],
    };
    const ja = (await pageTexts(await buildPdfReport(input([l])))).join(' ').replace(/\s+/g, '');
    for (const s of ['構成要素一覧', 'データフロー一覧', 'C1P3ユーザー登録', '管理主体：アプリ管理者', 'DF4', 'F4登録データ', 'DB接続（SQL）', '同期・書込み', 'TLS1.2+']) {
      expect(ja, s).toContain(s);
    }
    const en = (await pageTexts(await buildPdfReport(input([l], 'en')))).join(' ').replace(/\s+/g, '');
    expect(en).toContain('Dataflows');
    expect(en).toContain('Databaseconnection(SQL)');
  }, 30_000);

  it('layerData が無ければ構成要素一覧・データフロー一覧を出さない', async () => {
    const text = (await pageTexts(await buildPdfReport(input([layer('L0', 1)])))).join(' ');
    expect(text).not.toContain('データフロー一覧');
  }, 30_000);

  // 目視確認用：CRS_PDF_SAMPLE_OUT にパスを渡すとサンプルと 1 ページ目のテキストを書き出す。
  it.skipIf(!process.env.CRS_PDF_SAMPLE_OUT)('サンプル PDF を書き出す', async () => {
    const out = process.env.CRS_PDF_SAMPLE_OUT as string;
    const bytes = await buildPdfReport(input([layer('L0', 6), layer('L1', 18)]));
    fs.writeFileSync(out, bytes);
    fs.writeFileSync(`${out}.en.pdf`, await buildPdfReport(input([layer('L0', 6), layer('L1', 18)], 'en')));
    const pages = await pageTexts(bytes);
    if (pages) fs.writeFileSync(`${out}.page1.txt`, pages[0] ?? '');
  });
});
