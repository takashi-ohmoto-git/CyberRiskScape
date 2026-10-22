import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse as parseYaml } from 'yaml';
import {
  buildInvestigationReport,
  hostsMatch,
  parseHostMap,
  type HostMapEntry,
} from './buildInvestigationReport';
import { investigationReportToJson, investigationReportToMarkdown } from './investigationReportOutput';
import {
  artifactNameOf,
  buildVelociraptorEvidence,
  loadArtifactKnowledge,
  parseTriageEvidence,
  type HostEvidence,
  type VelociraptorRaw,
} from './evidence';
import type { InvestigationPlanInput } from '../investigation-plan/buildInvestigationPlan';
import { EMPTY_PROJECT_META, type DiagramEdge, type DiagramNode } from '../../core/model/types';
import { formatLocalDate } from '../../core/model/localDate';

const NOW = new Date(2026, 9, 23, 12, 0, 0);

const node = (id: string, seq: number, type: string, extra: Partial<DiagramNode> = {}): DiagramNode =>
  ({ id, seq, type, x: 0, y: 0, label: id, ...extra }) as unknown as DiagramNode;
const edge = (id: string, seq: number, source: string, target: string): DiagramEdge => ({
  id,
  seq,
  source,
  target,
  auth: 'None',
  network: 'Internet',
  encryption: 'Plain',
});

/** 攻撃者なし＝全ノード対象。C2 gw（保存期間の入力なし）/ C3 api（1 年以上）/ C4 db / C5 iot / C6 db2 / C7 api2（1 年以上）。 */
function input(): InvestigationPlanInput {
  return {
    nodes: [
      node('a', 1, 'THREAT_ACTOR'),
      node('gw', 2, 'GATEWAY'),
      node('api', 3, 'BACKEND_API', { posture: { logCollection: 'Collected', logRetention: 'OneYearOrMore' } }),
      node('db', 4, 'DATABASE'),
      node('iot', 5, 'IOT'),
      node('db2', 6, 'DATABASE'),
      node('api2', 7, 'BACKEND_API', { posture: { logCollection: 'Collected', logRetention: 'OneYearOrMore' } }),
    ],
    edges: [edge('e1', 1, 'a', 'gw')],
    threats: [],
    projectMeta: { ...EMPTY_PROJECT_META, systemName: 'Demo' },
    layer: 'L1',
  };
}

const triage = (over: Record<string, unknown> = {}) => ({
  format: 'cyberriskscape-triage',
  version: 1,
  host: 'x',
  collectedAt: '2026-10-22T09:00:00+09:00',
  parameters: {},
  scanned: [
    { path: '/var/log/messages', size: 10, lines: 2, firstTime: '2026-10-01T00:00:00', lastTime: '2026-10-22T00:00:00' },
    { path: '/var/log/old', size: 10, lines: 2, firstTime: '2026-09-20T00:00:00+09:00', lastTime: null },
  ],
  skipped: [],
  hits: [],
  correlations: [],
  extraUnknownKey: { ignored: true },
  ...over,
});
const tri = (over: Record<string, unknown>, path = 'r.json'): HostEvidence => {
  const r = parseTriageEvidence(triage(over), path);
  if (!r.ok) throw new Error(r.error);
  return r.evidence;
};

const hit = (n: number) =>
  Array.from({ length: n }, (_, i) => ({
    category: i % 2 ? 'crash' : 'oom',
    pattern: 'p',
    path: '/var/log/messages',
    line: i + 1,
    time: null,
    content: `line ${i}`,
    ip: null,
  }));

const velo = (over: Partial<VelociraptorRaw>): HostEvidence =>
  buildVelociraptorEvidence(
    { path: '/c', clientInfo: { Hostname: 'v', HostID: 'h' }, results: [], skipped: [], ...over },
    loadArtifactKnowledge(),
  );

const MAP: HostMapEntry[] = [
  { host: 'gw01', node: 'C2' },
  { host: 'web01', node: 'C3' },
  { host: 'db01', node: 'C4' },
  { host: 'db02', node: 'C6' },
  { host: 'web02', node: 'c7' },
  { host: 'ghost', node: 'C99' },
  { host: 'attacker-box', node: 'C1' },
];

const build = (evidence: HostEvidence[], rejected: { path: string; reason: string }[] = []) =>
  buildInvestigationReport(input(), evidence, MAP, rejected, NOW, 'ja');
const statusOf = (r: ReturnType<typeof build>, id: string) => r.nodes.find((n) => n.id === id)?.status;

describe('YAML（痕跡とみなす artifact）', () => {
  it('findings: true は FileFinder / Yara.Glob / LogGrep だけ。Pslist 等は参考情報', () => {
    const k = loadArtifactKnowledge().findings;
    for (const a of ['Linux.Search.FileFinder', 'Generic.Detection.Yara.Glob', 'Linux.Sys.LogGrep']) expect(k.get(a), a).toBe(true);
    for (const a of ['Linux.Sys.Pslist', 'Linux.Network.Netstat', 'Linux.Forensics.Journal', 'Linux.Syslog.SSHLogin']) {
      expect(k.get(a), a).toBe(false);
    }
    expect(k.has('Windows.Foo.Bar')).toBe(false);
  });

  it('英語オーバーレイは tools を触らない（findings の印は原本だけ）', () => {
    const en = parseYaml(readFileSync('data/investigation-templates/i18n/en/compromise.yaml', 'utf-8')) as {
      viewpoints: Record<string, Record<string, unknown>>;
    };
    for (const v of Object.values(en.viewpoints)) expect(v.tools).toBeUndefined();
  });
});

describe('トリアージ JSON の読み込み', () => {
  it('件数・分類・上位・観測した期間を取り出し、未知キーは無視する', () => {
    const e = tri({ hits: hit(7) });
    expect(e.source).toBe('triage');
    expect(e.traceCount).toBe(7);
    expect(e.categories).toEqual([
      { name: 'oom', count: 4 },
      { name: 'crash', count: 3 },
    ]);
    expect(e.top).toHaveLength(5);
    expect(e.observed).toEqual({ from: '2026-09-20', to: '2026-10-22' });
    expect(e.collectedAt).toBe('2026-10-22');
  });

  it('壊れた形は理由つきで失敗する', () => {
    expect(parseTriageEvidence({ format: 'cyberriskscape-triage', hits: 'x' }, 'p').ok).toBe(false);
    expect(parseTriageEvidence({ format: 'other' }, 'p').ok).toBe(false);
  });

  it('巨大な content は切り詰める', () => {
    const e = tri({ hits: [{ category: 'oom', content: 'a'.repeat(100000) }] });
    expect(e.top[0].content.length).toBeLessThanOrEqual(201);
  });
});

describe('Velociraptor の収集の組み立て', () => {
  it('%2F のソース名つきファイル名から artifact 名を取り、YAML に無いものは対応づけできない結果にする', () => {
    expect(artifactNameOf('Generic.Detection.WebShells%2FYaraHits.json')).toBe('Generic.Detection.WebShells');
    expect(artifactNameOf('Linux.Search.FileFinder.json')).toBe('Linux.Search.FileFinder');
    expect(artifactNameOf('Bad%ZZ.json')).toBe('Bad%ZZ');
    const e = velo({
      results: [
        { fileName: 'Linux.Search.FileFinder.json', rows: [{ FullPath: '/var/www/x.php' }], unreadable: [] },
        { fileName: 'Linux.Sys.Pslist.json', rows: [{ Pid: 1 }, { Pid: 2 }], unreadable: [] },
        { fileName: 'Generic.Detection.WebShells%2FYaraHits.json', rows: [{ a: 1 }], unreadable: [] },
      ],
    });
    expect(e.traceCount).toBe(1);
    expect(e.reference).toEqual([{ name: 'Linux.Sys.Pslist', count: 2 }]);
    expect(e.unmapped).toEqual([{ name: 'Generic.Detection.WebShells', count: 1 }]);
    expect(e.searched).toBe(true);
  });

  it('参考情報と YAML に無い artifact は痕跡にならない', () => {
    const e = velo({
      results: [
        { fileName: 'Linux.Sys.Pslist.json', rows: [{ Pid: 1 }], unreadable: [] },
        { fileName: 'Unknown.Artifact.json', rows: [{ x: 1 }], unreadable: [] },
      ],
    });
    expect(e.traceCount).toBe(0);
    expect(e.searched).toBe(false);
  });

  it('収集日時は log.json の最小 _ts（実行環境の日付）。Hostname が無ければ行の Fqdn', () => {
    const e = velo({
      clientInfo: undefined,
      minLogTs: 1760000000,
      results: [{ fileName: 'Linux.Sys.Pslist.json', rows: [{ Fqdn: 'web01.example.local' }], unreadable: [] }],
    });
    expect(e.collectedAt).toBe(formatLocalDate(new Date(1760000000 * 1000)));
    expect(e.host).toBe('web01.example.local');
    expect(e.observed).toBeUndefined();
  });
});

describe('ホスト名の照合', () => {
  it('大文字小文字を無視し、FQDN の先頭ラベルでも一致する。IP は分割しない', () => {
    expect(hostsMatch('WEB01', 'web01')).toBe(true);
    expect(hostsMatch('web01.example.local', 'web01')).toBe(true);
    expect(hostsMatch('web01', 'WEB01.Corp')).toBe(true);
    expect(hostsMatch('web01', 'web02')).toBe(false);
    expect(hostsMatch('10.0.0.1', '10.9.9.9')).toBe(false);
    expect(hostsMatch('', '')).toBe(false);
  });

  it('対応表のゆるい検証', () => {
    expect(parseHostMap({ hosts: [{ host: 'a', node: 'C1', extra: 1 }] }).ok).toBe(true);
    expect(parseHostMap({ hosts: [{ host: 'a' }] }).ok).toBe(false);
    expect(parseHostMap(null).ok).toBe(false);
  });
});

describe('buildInvestigationReport（4 状態）', () => {
  const evidence = [
    tri({ host: 'WEB01.example.local', hits: hit(3) }, 'web01.json'), // C3 痕跡あり
    tri({ host: 'db01' }, 'db01.json'), // C4 痕跡なし（観測値の期間）
    velo({ clientInfo: { Hostname: 'gw01' }, results: [{ fileName: 'Linux.Search.FileFinder.json', rows: [], unreadable: [] }] }), // C2 期間不明
    tri({ host: 'db02', skipped: [{ path: '/var/log/system.journal', reason: 'バイナリ' }] }, 'db02.json'), // C6 skipped
    velo({
      clientInfo: { Hostname: 'web02' },
      minLogTs: 1760000000,
      results: [{ fileName: 'Linux.Sys.LogGrep.json', rows: [], unreadable: [] }],
    }), // C7 保存期間から期間
    tri({ host: 'stray' }, 'stray.json'), // 対応表に無い
    tri({ host: 'ghost' }, 'ghost.json'), // 図に無いノード
    tri({ host: 'attacker-box' }, 'a.json'), // 対象外ノード（攻撃者）
  ];
  const report = build(evidence, [{ path: 'bad.json', reason: '壊れ' }]);

  it('痕跡あり・否定できない・未調査・痕跡なしがそれぞれ出て、重い順に並ぶ', () => {
    expect(statusOf(report, 'C3')).toBe('traces-found');
    expect(statusOf(report, 'C2')).toBe('not-negatable');
    expect(statusOf(report, 'C6')).toBe('not-negatable');
    expect(statusOf(report, 'C5')).toBe('not-investigated');
    expect(statusOf(report, 'C4')).toBe('no-traces');
    expect(statusOf(report, 'C7')).toBe('no-traces');
    const order = report.nodes.map((n) => n.status);
    const rank = ['traces-found', 'not-negatable', 'not-investigated', 'no-traces'];
    expect(order.map((s) => rank.indexOf(s))).toEqual([...order.map((s) => rank.indexOf(s))].sort((a, b) => a - b));
  });

  it('期間は観測値を優先し、無ければ図のログ保存期間から出す', () => {
    expect(report.nodes.find((n) => n.id === 'C4')?.period).toEqual({ basis: 'observed', from: '2026-09-20', to: '2026-10-22' });
    expect(report.nodes.find((n) => n.id === 'C7')?.period).toEqual({
      basis: 'retention',
      to: formatLocalDate(new Date(1760000000 * 1000)),
      retention: 'OneYearOrMore',
    });
    expect(report.nodes.find((n) => n.id === 'C2')?.period).toBeUndefined();
  });

  it('否定できない理由を列挙する', () => {
    expect(report.nodes.find((n) => n.id === 'C2')?.reasons).toEqual(['periodUnknown']);
    expect(report.nodes.find((n) => n.id === 'C6')?.reasons).toEqual(['skipped']);
  });

  it('図に無いホストは別枠。対応表に無い／ノードが図に無い／対象外のノードを区別する', () => {
    const byHost = Object.fromEntries(report.unknownHosts.map((u) => [u.evidence.host, u.reason]));
    expect(byHost).toEqual({
      stray: 'notInHostMap',
      ghost: 'nodeNotInDiagram',
      'attacker-box': 'nodeNotInScope',
    });
    expect(report.summary.unknownHosts).toBe(3);
    expect(report.summary.rejected).toBe(1);
  });

  it('対応づく証拠が無い痕跡は、他の状態に影響しない', () => {
    expect(report.nodes.some((n) => n.id === 'C1')).toBe(false);
  });
});

describe('出力', () => {
  const evidence = [tri({ host: 'web01', hits: [{ category: 'oom', path: '/p', line: 3, content: 'a`b\nc' }] })];
  const report = build(evidence);

  it('md の冒頭に免責と凡例があり、証拠の文字列はコードに閉じ込める', () => {
    const md = investigationReportToMarkdown(report);
    expect(md).toContain('この報告は侵害の有無を判定しない。痕跡が無いことは、侵害が無かったことの証明にならない。');
    expect(md).toContain('## 状態の凡例');
    expect(md.indexOf('痕跡あり: ')).toBeLessThan(md.indexOf('## ノードごとの状態'));
    expect(md).toContain('`a\'b c`');
    expect(md).toContain('作成日: 2026-10-23');
  });

  it('en の免責と JSON', () => {
    const en = buildInvestigationReport(input(), evidence, MAP, [], NOW, 'en');
    expect(investigationReportToMarkdown(en)).toContain(
      'This report does not determine whether a compromise occurred. The absence of traces is not proof that there was no compromise.',
    );
    const json = JSON.parse(investigationReportToJson(report));
    expect(json.kind).toBe('cyberriskscape-investigation-report');
    expect(json.nodes.find((n: { id: string }) => n.id === 'C3').status).toBe('traces-found');
  });
});
