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
});

describe('toCsv', () => {
  it('メタブロック → 空行 → ヘッダ → データ行の順で出力する', () => {
    const csv = toCsv(buildThreatReport(input([DETECTED])));
    const lines = csv.split('\r\n');
    expect(lines[0]).toBe('プロジェクト名,ProjectIT');
    expect(lines).toContain('脅威件数,1');
    const headerIdx = lines.indexOf('ID,対象要素,フレームワーク,カテゴリ,脅威,深刻度,緩和策,ステータス,コメント,種別');
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
    // sensitivity は section 2 で常に medium。
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

  it('DREAD なしは likelihood=possible、ありは段階推定', () => {
    expect(threatRows(md([T_HIGH]))[0][6]).toBe('possible');
    const scored: ThreatView = {
      ...T_HIGH,
      dread: { damage: 1, reproducibility: 3, exploitability: 3, affectedUsers: 1, discoverability: 1, at: 1 },
    };
    expect(threatRows(md([scored]))[0][6]).toBe('almost_certain'); // 3+3=6
  });

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

  it('8: 入力の threats（id/suppression/controlStatus/dread）を mutate しない', () => {
    const t: ThreatView = {
      ...T_HIGH,
      suppression: { status: 'accepted', note: 'x', at: 1 },
      controlStatus: { status: 'required', at: 2 },
      dread: { damage: 2, reproducibility: 2, exploitability: 2, affectedUsers: 2, discoverability: 2, at: 3 },
    };
    const arr = [t, T_CRIT];
    const snapshot = JSON.stringify(arr);
    toDCRHThreatModelMarkdown({ ...input(arr), edges: EDGES }, '2026-06-29');
    expect(JSON.stringify(arr)).toBe(snapshot);
    expect(arr[0].id).toBe('r-high'); // Tn 採番はローカルラベルに限定
  });
});
