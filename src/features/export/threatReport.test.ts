import { describe, expect, it } from 'vitest';
import {
  buildThreatReport,
  toCsv,
  toJson,
  toDCRHThreatModelMarkdown,
  THREAT_REPORT_KIND,
  THREAT_REPORT_SCHEMA_VERSION,
  type BuildThreatReportInput,
} from './threatReport';
import {
  EMPTY_PROJECT_META,
  type DiagramBoundary,
  type DiagramEdge,
  type DiagramNode,
  type ThreatView,
} from '../../core/model/types';

const NODES: DiagramNode[] = [
  { id: 'n1', seq: 1, type: 'LLM', x: 0, y: 0, label: 'GPT' },
  { id: 'n2', seq: 2, type: 'DB', x: 0, y: 0 },
];

const DETECTED: ThreatView = {
  id: 'rule-a-n1',
  ruleId: 'rule-a',
  subject: { kind: 'node', id: 'n1' },
  nodeId: 'n1',
  framework: 'AgenticAI',
  category: 'プロンプト注入',
  severity: 'High',
  description: 'ツール引数の注入',
  mitigation: '入力検証を行う',
  origin: 'detected',
};

const MANUAL: ThreatView = {
  id: 'mt1',
  subject: undefined,
  nodeId: '',
  framework: 'AgenticAI',
  category: '全体スコープの懸念',
  severity: 'Medium',
  description: '運用上の懸念',
  origin: 'manual',
  manualId: 'mt1',
};

function input(threats: ThreatView[]): BuildThreatReportInput {
  return {
    threats,
    nodes: NODES,
    edges: [],
    boundaries: [],
    projectMeta: { ...EMPTY_PROJECT_META, name: 'ProjectIT', systemName: 'CreditScoringAPI' },
    framework: 'AgenticAI',
    layer: 'L1',
  };
}

describe('buildThreatReport', () => {
  it('subject を ElementalID ＋ラベルに解決する', () => {
    const report = buildThreatReport(input([DETECTED]));
    expect(report.rows[0].asset).toBe('C1 GPT');
  });

  it('ラベル未設定ノードは型名をラベルに使う', () => {
    const t: ThreatView = { ...DETECTED, id: 't-n2', subject: { kind: 'node', id: 'n2' }, nodeId: 'n2' };
    const report = buildThreatReport(input([t]));
    expect(report.rows[0].asset).toBe('C2 DB');
  });

  it('subject 未設定（全体スコープ）の asset は空', () => {
    const report = buildThreatReport(input([MANUAL]));
    expect(report.rows[0].asset).toBe('');
  });

  it('検出脅威の未抑制は「未対応」', () => {
    expect(buildThreatReport(input([DETECTED])).rows[0].status).toBe('未対応');
  });

  it('リスク受容 / 誤検知の抑制状態を反映し note をコメントに出す', () => {
    const accepted: ThreatView = {
      ...DETECTED,
      suppression: { status: 'accepted', note: '残留リスク受容', at: 1 },
    };
    const fp: ThreatView = {
      ...DETECTED,
      id: 'rule-a-n1-fp',
      suppression: { status: 'false-positive', at: 2 },
    };
    const report = buildThreatReport(input([accepted, fp]));
    expect(report.rows[0].status).toBe('リスク受容');
    expect(report.rows[0].comments).toBe('残留リスク受容');
    expect(report.rows[1].status).toBe('誤検知');
    expect(report.rows[1].comments).toBe('');
  });

  it('手動脅威は種別「手動」・ステータス空', () => {
    const row = buildThreatReport(input([MANUAL])).rows[0];
    expect(row.origin).toBe('手動');
    expect(row.status).toBe('');
  });

  it('検出脅威は種別「自動検出」', () => {
    expect(buildThreatReport(input([DETECTED])).rows[0].origin).toBe('自動検出');
  });

  it('緩和策未設定は空文字', () => {
    const t: ThreatView = { ...DETECTED, mitigation: undefined };
    expect(buildThreatReport(input([t])).rows[0].countermeasure).toBe('');
  });

  it('リスク評価済みは severity（ルール由来）と effectiveSeverity（評価由来）が別の値になる', () => {
    const scored: ThreatView = {
      ...DETECTED,
      severity: 'Critical',
      risk: { damage: 1, affectedUsers: 1, reproducibility: 1, exploitability: 1, at: 1 },
    };
    const row = buildThreatReport(input([scored])).rows[0];
    expect(row.severity).toBe('Critical');
    expect(row.effectiveSeverity).toBe('Low');
    expect(row.impact).toBe('Low');
    expect(row.likelihood).toBe('Low');
  });

  it('リスク未評価は effectiveSeverity が severity と一致し impact/likelihood/risk が空', () => {
    const row = buildThreatReport(input([DETECTED])).rows[0];
    expect(row.effectiveSeverity).toBe(row.severity);
    expect(row.impact).toBe('');
    expect(row.likelihood).toBe('');
    expect(row.risk).toBeUndefined();
  });

  it('controlStatus は翻訳ラベルになり未設定は空文字', () => {
    const withStatus: ThreatView = {
      ...DETECTED,
      controlStatus: { status: 'implemented', note: '対応済', at: 1 },
    };
    expect(buildThreatReport(input([withStatus])).rows[0].controlStatus).toBe('実装済み');
    expect(buildThreatReport(input([DETECTED])).rows[0].controlStatus).toBe('');
  });

  it('脅威名（name）を出力する。未設定は空', () => {
    const named: ThreatView = { ...DETECTED, name: '脅威名テスト' };
    expect(buildThreatReport(input([named])).rows[0].name).toBe('脅威名テスト');
    expect(buildThreatReport(input([DETECTED])).rows[0].name).toBe('');
  });
});

describe('toCsv', () => {
  it('メタブロック → 空行 → ヘッダ → データ行の順で出力する', () => {
    const csv = toCsv(buildThreatReport(input([DETECTED])));
    const lines = csv.split('\r\n');
    expect(lines[1]).toBe('プロジェクト名,ProjectIT');
    expect(lines).toContain('脅威件数,1');
    const headerIdx = lines.indexOf(
      'ID,対象要素,フレームワーク,カテゴリ,脅威名,脅威,ルール深刻度,実効深刻度,Impact,Likelihood,緩和策,対応状況,対策実装状況,コメント,種別',
    );
    expect(headerIdx).toBeGreaterThan(0);
    expect(lines[headerIdx - 1]).toBe(''); // 空行で区切る
    expect(lines[headerIdx + 1]).toContain('rule-a-n1');
    expect(lines[headerIdx + 1]).toContain('C1 GPT');
  });

  it('カンマ・改行・ダブルクオートを含む値をエスケープする', () => {
    const tricky: ThreatView = {
      ...DETECTED,
      description: 'a,b"c\nd',
    };
    const csv = toCsv(buildThreatReport(input([tricky])));
    expect(csv).toContain('"a,b""c\nd"');
  });

  it('CRLF 改行を使う', () => {
    expect(toCsv(buildThreatReport(input([])))).toContain('\r\n');
  });

  it('1 行目にスキーマバージョンを出す（下流が版を見分けられるようにする）', () => {
    const lines = toCsv(buildThreatReport(input([DETECTED]))).split('\r\n');
    expect(lines[0]).toBe(`スキーマバージョン,${THREAT_REPORT_SCHEMA_VERSION}`);
  });

  it('脅威名が CSV 行に出る', () => {
    const named: ThreatView = { ...DETECTED, name: '脅威名テスト' };
    const csv = toCsv(buildThreatReport(input([named])));
    expect(csv).toContain('脅威名テスト');
  });
});

describe('toJson', () => {
  it('schemaVersion / kind / project / threats を含む', () => {
    const json = JSON.parse(toJson(buildThreatReport(input([DETECTED]))));
    expect(json.schemaVersion).toBe(THREAT_REPORT_SCHEMA_VERSION);
    expect(json.kind).toBe(THREAT_REPORT_KIND);
    expect(json.framework).toBe('AgenticAI');
    expect(json.layer).toBe('L1');
    expect(json.project.name).toBe('ProjectIT');
    expect(json.threats).toHaveLength(1);
    expect(json.threats[0].asset).toBe('C1 GPT');
  });

  it('risk は生値（4 項目）を持ち、CSV には出ない', () => {
    const scored: ThreatView = {
      ...DETECTED,
      risk: { damage: 2, affectedUsers: 3, reproducibility: 1, exploitability: 2, at: 123 },
    };
    const report = buildThreatReport(input([scored]));
    const json = JSON.parse(toJson(report));
    expect(json.threats[0].risk).toEqual({
      damage: 2,
      affectedUsers: 3,
      reproducibility: 1,
      exploitability: 2,
      at: 123,
    });
    expect(toCsv(report)).not.toContain('damage');
  });

  it('ルール由来の根拠フィールドを JSON に出し、CSV の 15 列は変えない', () => {
    const rich: ThreatView = {
      ...DETECTED,
      canonicalId: 'prompt-injection',
      isCustom: true,
      mitigationTiers: { foundation: '入力検証', advanced: 'プロベナンス記録' },
      complianceRefs: [{ standard: 'NIST AI RMF', ref: 'GOVERN 1.1' }],
      references: [{ title: 'OWASP LLM Top 10', url: 'https://example.com/llm01' }],
      corroboration: { ruleIds: ['rule-a-n1', 'rule-b-n1'], frameworks: ['AgenticAI', 'AI'] },
      assumptionFlags: ['attackSurface'],
    };
    const report = buildThreatReport(input([rich]));
    const row = JSON.parse(toJson(report)).threats[0];
    expect(row.canonicalId).toBe('prompt-injection');
    expect(row.isCustom).toBe(true);
    expect(row.mitigationTiers).toEqual({ foundation: '入力検証', advanced: 'プロベナンス記録' });
    expect(row.complianceRefs).toEqual([{ standard: 'NIST AI RMF', ref: 'GOVERN 1.1' }]);
    expect(row.references).toEqual([
      { title: 'OWASP LLM Top 10', url: 'https://example.com/llm01' },
    ]);
    expect(row.corroboration).toEqual({
      ruleIds: ['rule-a-n1', 'rule-b-n1'],
      frameworks: ['AgenticAI', 'AI'],
    });
    expect(row.assumptionFlags).toEqual(['attackSurface']);

    // CSV は 15 列のまま（列の増減がないこと＝v2 の下流を壊さない）。
    const lines = toCsv(report).split('\r\n');
    const header = lines.find((l) => l.startsWith('ID,'));
    expect(header?.split(',')).toHaveLength(15);
    expect(toCsv(report)).not.toContain('GOVERN 1.1');
  });

  it('根拠フィールドを持たない脅威では各キーが undefined（JSON に出ない）', () => {
    const json = toJson(buildThreatReport(input([DETECTED])));
    expect(json).not.toContain('complianceRefs');
    expect(json).not.toContain('canonicalId');
  });
});

// ─── DCRH（Anthropic 公式 THREAT_MODEL.md）エクスポート ──────────────
describe('toDCRHThreatModelMarkdown', () => {
  const EDGES: DiagramEdge[] = [
    {
      id: 'e1',
      seq: 1,
      source: 'n1',
      target: 'n2',
      auth: 'None',
      network: 'Internet',
      encryption: 'TLS',
      dataFlowName: 'query',
    },
  ];

  // n1（High）, n2（Critical）, エッジ起点（Medium）の 3 件。
  const T_HIGH: ThreatView = { ...DETECTED, id: 'r-high', severity: 'High' };
  const T_CRIT: ThreatView = {
    ...DETECTED,
    id: 'r-crit',
    subject: { kind: 'node', id: 'n2' },
    nodeId: 'n2',
    severity: 'Critical',
    description: 'DB 全件流出',
  };
  const T_EDGE: ThreatView = {
    ...DETECTED,
    id: 'r-edge',
    subject: { kind: 'edge', id: 'e1' },
    nodeId: 'n1',
    severity: 'Medium',
    description: '経路上の改ざん',
  };

  function md(threats: ThreatView[], date?: string): string {
    return toDCRHThreatModelMarkdown(
      { ...input(threats), edges: EDGES },
      date,
    );
  }

  /** section 2 のデータ行（asset / description / sensitivity）を抽出。 */
  function assetRows(text: string): string[][] {
    const lines = text.split('\n');
    const start = lines.findIndex((l) => l === '## 2. Assets');
    const end = lines.findIndex((l, i) => i > start && l.startsWith('## 3.'));
    return lines
      .slice(start, end)
      .filter((l) => l.startsWith('| ') && !l.startsWith('| asset') && !l.startsWith('|---'))
      .map((l) => l.slice(2, -2).split(' | '));
  }

  /** section 4 のデータ行（| T... で始まる行）を抽出。 */
  function threatRows(text: string): string[][] {
    const lines = text.split('\n');
    const start = lines.findIndex((l) => l === '## 4. Threats');
    const end = lines.findIndex((l, i) => i > start && l.startsWith('## 5.'));
    return lines
      .slice(start, end)
      .filter((l) => /^\| T\d+ /.test(l))
      .map((l) => l.slice(2, -2).split(' | '));
  }

  it('1: 必須見出しが順序通りに出力される', () => {
    const text = md([T_HIGH, T_CRIT, T_EDGE]);
    const heads = [
      '# Threat Model:',
      '## 1. System context',
      '## 2. Assets',
      '## 3. Entry points & trust boundaries',
      '## 4. Threats',
      '## 5. Deprioritized',
      '## 6. Open questions',
      '## 7. Provenance',
    ];
    let cursor = -1;
    for (const h of heads) {
      const idx = text.indexOf(h);
      expect(idx, h).toBeGreaterThan(cursor);
      cursor = idx;
    }
  });

  it('2: enum 値が全行で許容集合に収まる', () => {
    const ACTOR = new Set([
      '',
      'remote_unauth',
      'remote_auth',
      'adjacent_network',
      'local_user',
      'local_admin',
      'supply_chain',
      'insider',
    ]);
    const IMPACT = new Set(['low', 'medium', 'high', 'critical', 'existential']);
    const LIKELIHOOD = new Set(['very_rare', 'rare', 'possible', 'likely', 'almost_certain']);
    const STATUS = new Set(['unmitigated', 'partially_mitigated', 'mitigated', 'risk_accepted']);
    for (const cols of threatRows(md([T_HIGH, T_CRIT, T_EDGE]))) {
      const [, , actor, , , impact, likelihood, status] = cols;
      expect(ACTOR.has(actor)).toBe(true);
      expect(IMPACT.has(impact)).toBe(true);
      expect(LIKELIHOOD.has(likelihood)).toBe(true);
      expect(STATUS.has(status)).toBe(true);
    }
    // sensitivity（section 2）も許容集合に収まる。未評価なので既定 medium。
    const SENSITIVITY = new Set(['low', 'medium', 'high', 'critical']);
    for (const cols of assetRows(md([T_HIGH, T_CRIT, T_EDGE]))) {
      expect(SENSITIVITY.has(cols[2])).toBe(true);
    }
    expect(md([T_HIGH])).toMatch(/\| medium \|$/m);
  });

  it('3: (impact, likelihood) 降順で T1.. 連番採番、id は書き換えない', () => {
    const rows = threatRows(md([T_HIGH, T_CRIT, T_EDGE]));
    expect(rows.map((c) => c[0])).toEqual(['T1', 'T2', 'T3']);
    // Critical → High → Medium の順。
    expect(rows.map((c) => c[5])).toEqual(['critical', 'high', 'medium']);
    // 末尾の対応表は元 id を保持する。
    const text = md([T_HIGH, T_CRIT, T_EDGE]);
    expect(text).toMatch(/<!-- crs-id-map: T1=r-crit; T2=r-high; T3=r-edge; -->/);
  });

  it('4: section 3 の各 entry_point が section 4 の surface に出現する', () => {
    const text = md([T_HIGH, T_CRIT, T_EDGE]);
    const lines = text.split('\n');
    const s3start = lines.findIndex((l) => l.startsWith('## 3.'));
    const s3end = lines.findIndex((l, i) => i > s3start && l.startsWith('## 4.'));
    const entryPoints = lines
      .slice(s3start, s3end)
      .filter((l) => l.startsWith('| ') && !l.startsWith('| entry_point') && !l.startsWith('|---'))
      .map((l) => l.slice(2).split(' | ')[0]);
    expect(entryPoints.length).toBeGreaterThan(0); // エッジ起点脅威があるので非空
    const surfaces = new Set(threatRows(text).map((c) => c[3]));
    for (const ep of entryPoints) expect(surfaces.has(ep)).toBe(true);
  });

  it('5: evidence 列は常に空', () => {
    for (const cols of threatRows(md([T_HIGH, T_CRIT, T_EDGE]))) {
      expect(cols[9]).toBe('');
    }
  });

  it('6: 表セルの | と改行をエスケープする', () => {
    const tricky: ThreatView = { ...T_HIGH, description: 'a|b\nc' };
    const text = md([tricky]);
    expect(text).toContain('a\\|b<br>c');
    expect(text).not.toContain('a|b'); // 生のパイプは残らない
  });

  it('F-1: section 4 の impact は実効 severity から決まる（ルール由来ではない）', () => {
    const scored: ThreatView = {
      ...T_HIGH,
      severity: 'Critical',
      risk: { damage: 1, affectedUsers: 1, reproducibility: 1, exploitability: 1, at: 1 },
    };
    expect(threatRows(md([scored]))[0][5]).toBe('low');
  });

  it('F-2/F-3: BLAST_RADIUS 境界は section 2 Assets に出ない。blastRadiusLabel は資産ラベルに使われる', () => {
    const boundary: DiagramBoundary = {
      id: 'blast1',
      seq: 1,
      type: 'BLAST_RADIUS',
      x: 0,
      y: 0,
      width: 10,
      height: 10,
      trustLevel: 'Internal',
      blastRadiusLabel: '決済系の侵害範囲',
    };
    const boundaryThreat: ThreatView = {
      ...T_HIGH,
      id: 'r-boundary',
      subject: { kind: 'boundary', id: 'blast1' },
    };
    const withBoundary = { ...input([boundaryThreat]), edges: EDGES, boundaries: [boundary] };

    const text = toDCRHThreatModelMarkdown(withBoundary);
    expect(text).not.toContain('| BLAST_RADIUS |'); // section 2 に出ない

    const csv = toCsv(buildThreatReport(withBoundary));
    expect(csv).toContain('決済系の侵害範囲'); // CSV の asset 列にはラベルが出る
  });

  it('status マッピング：implemented→mitigated / accepted→risk_accepted', () => {
    const impl: ThreatView = {
      ...T_HIGH,
      controlStatus: { status: 'implemented', note: '実装済', at: 1 },
    };
    expect(threatRows(md([impl]))[0][7]).toBe('mitigated');

    const accepted: ThreatView = {
      ...T_HIGH,
      suppression: { status: 'accepted', note: '受容理由', at: 1 },
    };
    const text = md([accepted]);
    expect(threatRows(text)[0][7]).toBe('risk_accepted');
    expect(text).toContain('リスク受容：受容理由'); // section 5 にも理由付きで載る

    const reduce: ThreatView = { ...T_HIGH, suppression: { status: 'reduce', at: 1 } };
    expect(threatRows(md([reduce]))[0][7]).toBe('partially_mitigated');
  });

  it('false-positive は section 4 から除外し section 5 に載せる', () => {
    const fp: ThreatView = { ...T_HIGH, suppression: { status: 'false-positive', at: 1 } };
    const text = md([fp]);
    expect(threatRows(text)).toHaveLength(0);
    expect(text).toContain('誤検知として除外');
  });

  it('controlStatus=not-applicable は section 4 から外し section 5 へ', () => {
    const na: ThreatView = {
      ...T_HIGH,
      controlStatus: { status: 'not-applicable', note: '該当環境なし', at: 1 },
    };
    const text = md([na]);
    expect(threatRows(text)).toHaveLength(0);
    expect(text).toContain('対策対象外（not-applicable）：該当環境なし');
  });

  it('リスク評価なしは likelihood=possible', () => {
    expect(threatRows(md([T_HIGH]))[0][6]).toBe('possible');
  });

  // DCRH の likelihood は 5 段階なので、アプリ内の 3 段階へ畳む前の
  // reproducibility + exploitability（2..6）をそのまま使う（解像度を落とさない）。
  it.each([
    [1, 1, 'very_rare'],
    [1, 2, 'rare'],
    [2, 2, 'possible'],
    [2, 3, 'likely'],
    [3, 3, 'almost_certain'],
  ] as const)(
    'reproducibility=%i + exploitability=%i → likelihood=%s',
    (reproducibility, exploitability, expected) => {
      const scored: ThreatView = {
        ...T_HIGH,
        risk: { damage: 1, affectedUsers: 1, reproducibility, exploitability, at: 1 },
      };
      expect(threatRows(md([scored]))[0][6]).toBe(expected);
    },
  );

  it('provenance に mode/date/tool を出力する', () => {
    const text = md([T_HIGH], '2026-06-29');
    expect(text).toContain('- mode: cyberriskscape-export');
    expect(text).toContain('- date: 2026-06-29');
    expect(text).toContain('- tool: CyberRiskScape');
  });

  it('7: 回帰ガード — toCsv/toJson は DCRH 実行前後でバイト同一', () => {
    const base = input([DETECTED]);
    const csvBefore = toCsv(buildThreatReport(base));
    const jsonBefore = toJson(buildThreatReport(base));
    toDCRHThreatModelMarkdown({ ...base, edges: EDGES });
    expect(toCsv(buildThreatReport(base))).toBe(csvBefore);
    expect(toJson(buildThreatReport(base))).toBe(jsonBefore);
  });

  it('8: 入力の threats（id/suppression/controlStatus/risk）を mutate しない', () => {
    const t: ThreatView = {
      ...T_HIGH,
      suppression: { status: 'accepted', note: 'x', at: 1 },
      controlStatus: { status: 'required', at: 2 },
      risk: { damage: 2, reproducibility: 2, exploitability: 2, affectedUsers: 2, at: 3 },
    };
    const arr = [t, T_CRIT];
    const snapshot = JSON.stringify(arr);
    toDCRHThreatModelMarkdown({ ...input(arr), edges: EDGES }, '2026-06-29');
    expect(JSON.stringify(arr)).toBe(snapshot);
    expect(arr[0].id).toBe('r-high'); // Tn 採番はローカルラベルに限定
  });

  // ── section 2 sensitivity（Damage 由来・アセット単位で最大値） ──

  it('sensitivity は Damage から引く（1=low / 2=medium / 3=high）', () => {
    const scored = (damage: 1 | 2 | 3): ThreatView => ({
      ...T_HIGH,
      risk: { damage, affectedUsers: 1, reproducibility: 1, exploitability: 1, at: 1 },
    });
    expect(assetRows(md([scored(1)]))[0]).toEqual(['C1 GPT', 'LLM', 'low']);
    expect(assetRows(md([scored(2)]))[0]).toEqual(['C1 GPT', 'LLM', 'medium']);
    expect(assetRows(md([scored(3)]))[0]).toEqual(['C1 GPT', 'LLM', 'high']);
  });

  it('同一アセットに複数の評価があるときは Damage の最大値を採る', () => {
    const low: ThreatView = {
      ...T_HIGH,
      id: 'r-low',
      risk: { damage: 1, affectedUsers: 1, reproducibility: 1, exploitability: 1, at: 1 },
    };
    const high: ThreatView = {
      ...T_HIGH,
      id: 'r-hi',
      risk: { damage: 3, affectedUsers: 1, reproducibility: 1, exploitability: 1, at: 2 },
    };
    // 並び順に依存しないこと（低い方を後に評価しても下がらない）。
    expect(assetRows(md([low, high]))[0][2]).toBe('high');
    expect(assetRows(md([high, low]))[0][2]).toBe('high');
  });

  it('エッジ起点の脅威は到達先ノードの sensitivity に効く', () => {
    const edgeScored: ThreatView = {
      ...T_EDGE,
      risk: { damage: 3, affectedUsers: 1, reproducibility: 1, exploitability: 1, at: 1 },
    };
    const rows = assetRows(md([edgeScored]));
    expect(rows[0]).toEqual(['C1 GPT', 'LLM', 'medium']); // 起点ノードは据え置き
    expect(rows[1]).toEqual(['C2 DB', 'DB', 'high']); // 到達先 n2 に効く
  });

  it('section 5 送り（誤検知 / 適用外）の Damage は sensitivity に数えない', () => {
    const fp: ThreatView = {
      ...T_HIGH,
      suppression: { status: 'false-positive', at: 1 },
      risk: { damage: 3, affectedUsers: 1, reproducibility: 1, exploitability: 1, at: 1 },
    };
    const na: ThreatView = {
      ...T_HIGH,
      id: 'r-na',
      controlStatus: { status: 'not-applicable', note: '該当なし', at: 1 },
      risk: { damage: 3, affectedUsers: 1, reproducibility: 1, exploitability: 1, at: 1 },
    };
    expect(assetRows(md([fp, na]))[0][2]).toBe('medium');
  });

  it('未評価アセットは medium ＋ section 6 に既定値の注記を出す', () => {
    const text = md([T_HIGH]);
    expect(assetRows(text)[0][2]).toBe('medium');
    expect(text).toContain('sensitivity を既定 `medium` としている');
  });

  it('全アセットが評価済みなら既定値の注記は出ない', () => {
    const r = { affectedUsers: 1, reproducibility: 1, exploitability: 1, at: 1 } as const;
    const n1: ThreatView = { ...T_HIGH, risk: { damage: 2, ...r } };
    const n2: ThreatView = { ...T_CRIT, risk: { damage: 3, ...r } };
    const text = md([n1, n2]);
    expect(assetRows(text).map((c) => c[2])).toEqual(['medium', 'high']);
    expect(text).not.toContain('sensitivity を既定 `medium` としている');
    // 由来の説明そのものは常に出す。
    expect(text).toContain('Damage の最大値から推定');
  });
});

// ─── 認証基盤インベントリ（第 2 ブロック / JSON 別キー） ──────────────
describe('identityInventory', () => {
  const IDP: DiagramNode = {
    id: 'idp',
    seq: 3,
    type: 'IDENTITY_PROVIDER',
    x: 0,
    y: 0,
    label: 'Entra ID',
    identityProviderKind: 'IDaaS',
  };
  const APP: DiagramNode = { id: 'app', seq: 4, type: 'PROCESS', x: 0, y: 0, label: '業務アプリ' };
  // e1: app が idp を発行元として宣言（Tier 1）。e2: idp と n2(DB) が直接つながる（Tier 2）。
  const EDGES: DiagramEdge[] = [
    { id: 'e1', seq: 1, source: 'n1', target: 'app', auth: 'MFA', network: 'VPC', encryption: 'TLS', authProviderId: 'idp' },
    { id: 'e2', seq: 2, source: 'idp', target: 'n2', auth: 'MFA', network: 'VPC', encryption: 'TLS' },
  ];
  const withIdp: BuildThreatReportInput = {
    ...input([DETECTED]),
    nodes: [...NODES, IDP, APP],
    edges: EDGES,
  };

  it('発行元 1 件＝1 行で Tier 1 / Tier 2 を解決する', () => {
    const inv = buildThreatReport(withIdp).identityInventory;
    expect(inv).toHaveLength(1);
    expect(inv[0].provider).toBe('C3 Entra ID');
    expect(inv[0].kind).toBe('IDaaS');
    expect(inv[0].dependents).toEqual(['C4 業務アプリ']);
    expect(inv[0].directPeers).toEqual(['C2 DB']);
  });

  it('発行元になり得るノードが無ければ空配列で、CSV に第 2 ブロックを出さない', () => {
    const report = buildThreatReport(input([DETECTED]));
    expect(report.identityInventory).toEqual([]);
    expect(toCsv(report)).not.toContain('認証基盤インベントリ');
  });

  it('CSV は脅威表の後ろに見出し → ヘッダ → 行の順で出す', () => {
    const lines = toCsv(buildThreatReport(withIdp)).split('\r\n');
    const threatHeader = lines.findIndex((l) => l.startsWith('ID,'));
    const invHeading = lines.indexOf('認証基盤インベントリ,1');
    expect(invHeading).toBeGreaterThan(threatHeader);
    expect(lines[invHeading - 1]).toBe(''); // 空行で区切る
    expect(lines[invHeading + 1]).toBe('発行元,種別,依存先件数,依存先,直接接続件数,直接接続');
    expect(lines[invHeading + 2]).toBe('C3 Entra ID,IDaaS,1,C4 業務アプリ,1,C2 DB');
  });

  it('依存先が複数のときは `; ` で連結する', () => {
    const app2: DiagramNode = { id: 'app2', seq: 5, type: 'PROCESS', x: 0, y: 0, label: 'アプリ B' };
    const e3: DiagramEdge = { id: 'e3', seq: 3, source: 'n1', target: 'app2', auth: 'MFA', network: 'VPC', encryption: 'TLS', authProviderId: 'idp' };
    const inv = buildThreatReport({
      ...withIdp,
      nodes: [...withIdp.nodes, app2],
      edges: [...EDGES, e3],
    }).identityInventory;
    expect(inv[0].dependents).toEqual(['C4 業務アプリ', 'C5 アプリ B']);
    const lines = toCsv(buildThreatReport({
      ...withIdp,
      nodes: [...withIdp.nodes, app2],
      edges: [...EDGES, e3],
    })).split('\r\n');
    expect(lines.some((l) => l.includes('C4 業務アプリ; C5 アプリ B'))).toBe(true);
  });

  it('JSON は配列のまま identityInventory に出す', () => {
    const json = JSON.parse(toJson(buildThreatReport(withIdp)));
    expect(json.identityInventory).toEqual([
      {
        provider: 'C3 Entra ID',
        kind: 'IDaaS',
        dependents: ['C4 業務アプリ'],
        directPeers: ['C2 DB'],
      },
    ]);
  });

  it('DCRH には出さない（section 構成は下流との契約）', () => {
    const md = toDCRHThreatModelMarkdown(withIdp, '2026-09-23');
    expect(md).not.toContain('認証基盤インベントリ');
    expect(md).not.toContain('Identity provider inventory');
  });
});
