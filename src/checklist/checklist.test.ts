import { describe, expect, it } from 'vitest';
import { BUNDLED_CHECKLISTS, findOrphanChecklistOverlays, getChecklists } from './bundled';
import { ChecklistLoadError, parseChecklistFile } from './loader';
import { evaluateChecklist, type ChecklistResult } from './evaluate';
import { toChecklistCsv, toChecklistJson, toChecklistMarkdown } from './report';
import { componentRegistry } from '../component-library/defaultRegistry';
import { BUNDLED_THREAT_LIBRARY, getThreatLibrary } from '../threat-library/loader/bundledLibrary';
import { detectThreats } from '../core/threat-engine/detectThreats';
import { buildThreatViews } from '../core/threat-engine/buildThreatViews';
import {
  EMPTY_PROJECT_META,
  type DiagramEdge,
  type DiagramNode,
  type ControlStatusValue,
  type SuppressionState,
  type ThreatView,
} from '../core/model/types';

const IPA = BUNDLED_CHECKLISTS.find((c) => c.checklist.id === 'ipa-alert-2026-10')!;

describe('ipa-alert-2026-10.yaml', () => {
  it('スキーマを通り、17 項目（7 / 6 / 4）を含む', () => {
    expect(IPA).toBeDefined();
    expect(IPA.groups.map((g) => g.items.length)).toEqual([7, 6, 4]);
    expect(IPA.checklist.staleDays).toBe(30);
  });

  it('項目 id が一意', () => {
    const ids = IPA.groups.flatMap((g) => g.items.map((i) => i.id));
    expect(new Set(ids).size).toBe(17);
  });

  it('targetTypes がすべて同梱のコンポーネントライブラリに存在する', () => {
    const missing = IPA.groups.flatMap((g) =>
      g.items.flatMap((i) => i.targetTypes.filter((t) => !componentRegistry.has(t)).map((t) => `${i.id}:${t}`)),
    );
    expect(missing).toEqual([]);
  });

  it('ruleIds がすべて同梱の脅威ライブラリに存在する', () => {
    const known = new Set(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.id));
    const missing = IPA.groups.flatMap((g) =>
      g.items.flatMap((i) => i.ruleIds.filter((r) => !known.has(r)).map((r) => `${i.id}:${r}`)),
    );
    expect(missing).toEqual([]);
  });

  it('en オーバーレイが全項目のタイトルと確かめ方を訳しており、孤立も無い', () => {
    const en = getChecklists('en').find((c) => c.checklist.id === IPA.checklist.id)!;
    for (const g of IPA.groups) {
      const eg = en.groups.find((x) => x.id === g.id)!;
      expect(eg.title).not.toBe(g.title);
      for (const i of g.items) {
        const ei = eg.items.find((x) => x.id === i.id)!;
        expect(ei.title).not.toBe(i.title);
        expect(ei.howTo).not.toBe(i.howTo);
        expect(ei.ruleIds).toEqual(i.ruleIds);
      }
    }
    expect(findOrphanChecklistOverlays('en')).toEqual([]);
  });
});

describe('parseChecklistFile', () => {
  it('項目 id の重複を拒否する', () => {
    const dup = `schemaVersion: 1
checklist:
  id: x
  title: t
  source: { publisher: p, title: t, url: "https://example.com", publishedAt: "2026-01-01" }
  staleDays: 30
groups:
  - id: g
    title: g
    items:
      - { id: a, title: t, howTo: h, targetTypes: [USER], ruleIds: [r] }
      - { id: a, title: t, howTo: h, targetTypes: [USER], ruleIds: [r] }
`;
    expect(() => parseChecklistFile(dup, 'dup.yaml')).toThrow(ChecklistLoadError);
  });

  it('未知のキーを拒否する（strict）', () => {
    expect(() => parseChecklistFile('schemaVersion: 1\nchecklist: {}\ngroups: []\nextra: 1\n', 'bad.yaml')).toThrow(
      ChecklistLoadError,
    );
  });
});

// ── 判定 ──
const n = (id: string, type: string, seq: number, extra: Partial<DiagramNode> = {}): DiagramNode => ({
  id,
  type,
  x: 0,
  y: 0,
  seq,
  ...extra,
});

const threat = (ruleId: string, nodeId: string, extra: Partial<ThreatView> = {}): ThreatView => ({
  id: `${ruleId}-${nodeId}`,
  ruleId,
  origin: 'detected',
  nodeId,
  subject: { kind: 'node', id: nodeId },
  framework: 'STRIDE',
  category: 'c',
  severity: 'High',
  description: 'd',
  ...extra,
});

const supp = (status: SuppressionState['status']): SuppressionState => ({ status, at: 0 });

const ASOF = '2026-10-10';

// ipa-01 = [FRONT_END_SERVER, GATEWAY, ...] / ruleIds に stride-web-global-ip-exposure-001 を含む
const evalWith = (nodes: DiagramNode[], threats: ThreatView[], asOf: Date | string = ASOF): ChecklistResult =>
  evaluateChecklist({ checklist: IPA, nodes, threats, asOf });
const item = (r: ChecklistResult, id: string) => r.groups.flatMap((g) => g.items).find((i) => i.item.id === id)!;

describe('evaluateChecklist', () => {
  const web = n('w', 'FRONT_END_SERVER', 3, { label: '公開 Web' });

  it('対象の型のノードも検出も無ければ「対象なし」', () => {
    const r = evalWith([n('u', 'USER', 1)], []);
    expect(item(r, 'ipa-01').status).toBe('notApplicable');
    expect(r.summary.notApplicable).toBeGreaterThan(0);
  });

  it('対象の型のノードが無くても、項目のルールの検出があれば検出に従う', () => {
    const r = evalWith([n('u', 'USER', 1)], [threat('stride-web-global-ip-exposure-001', 'u')]);
    expect(item(r, 'ipa-01').status).toBe('action');
    expect(item(r, 'ipa-01').targetNodeCount).toBe(0);
  });

  it('対象があり検出が無ければ「問題なし」', () => {
    const r = evalWith([web], []);
    expect(item(r, 'ipa-01').status).toBe('ok');
    expect(item(r, 'ipa-01').nodes).toEqual([]);
  });

  it('未入力由来でない検出が 1 件でもあれば「要対応」。関係ノードは C{seq} 名前', () => {
    const r = evalWith(
      [web],
      [
        threat('stride-web-global-ip-exposure-001', 'w', { assumptionFlags: ['attackSurface'] }),
        threat('webserver-webshell-implant-001', 'w'),
      ],
    );
    const it1 = item(r, 'ipa-01');
    expect(it1.status).toBe('action');
    expect(it1.counts).toEqual({ action: 1, unfilled: 1, accepted: 0, implemented: 0 });
    expect(it1.nodes).toEqual([{ id: 'w', label: 'C3 公開 Web' }]);
    expect(it1.checkNodes).toEqual([{ id: 'w', label: 'C3 公開 Web' }]);
    expect(it1.checkThreats.map((c) => c.kind)).toEqual(['unfilled', 'action']);
    expect(it1.checkThreats[1].node).toEqual({ id: 'w', label: 'C3 公開 Web' });
  });

  it('検出がすべて attackSurface / posture の未入力由来なら「未入力」', () => {
    const r = evalWith(
      [web],
      [
        threat('stride-web-global-ip-exposure-001', 'w', { assumptionFlags: ['attackSurface'] }),
        threat('posture-patch-missing-001', 'w', { assumptionFlags: ['posture'] }),
      ],
    );
    expect(item(r, 'ipa-01').status).toBe('unfilled');
  });

  it('agentAttributes だけのフラグは未入力扱いにしない', () => {
    const r = evalWith([web], [threat('stride-web-global-ip-exposure-001', 'w', { assumptionFlags: ['agentAttributes'] })]);
    expect(item(r, 'ipa-01').status).toBe('action');
  });

  it('検出がすべてリスク受容なら「リスク受容」。未入力が混じれば「未入力」', () => {
    const accepted = threat('stride-web-global-ip-exposure-001', 'w', { suppression: supp('accepted') });
    expect(item(evalWith([web], [accepted]), 'ipa-01').status).toBe('accepted');
    const unfilled = threat('webserver-webshell-implant-001', 'w', { assumptionFlags: ['attackSurface'] });
    expect(item(evalWith([web], [accepted, unfilled]), 'ipa-01').status).toBe('unfilled');
    expect(item(evalWith([web], [accepted, unfilled]), 'ipa-01').checkNodes).toEqual([{ id: 'w', label: 'C3 公開 Web' }]);
    expect(item(evalWith([web], [accepted]), 'ipa-01').checkNodes).toEqual([]);
  });

  it('誤検知は除外する（残りが無ければ「問題なし」）。回避・低減・移転は要対応のまま', () => {
    const fp = threat('stride-web-global-ip-exposure-001', 'w', { suppression: supp('false-positive') });
    expect(item(evalWith([web], [fp]), 'ipa-01').status).toBe('ok');
    const reduce = threat('stride-web-global-ip-exposure-001', 'w', { suppression: supp('reduce') });
    expect(item(evalWith([web], [reduce]), 'ipa-01').status).toBe('action');
  });

  it('対策実装済みは「対策済み」に数え、確認が必要なノードから外す。対策不要は数えない。要対応・却下は要対応のまま', () => {
    const cs = (status: ControlStatusValue) => ({ controlStatus: { status, at: 0 } });
    const done = threat('stride-web-global-ip-exposure-001', 'w', { assumptionFlags: ['attackSurface'], ...cs('implemented') });
    const it1 = item(evalWith([web], [done]), 'ipa-01');
    expect(it1.status).toBe('ok');
    expect(it1.counts).toEqual({ action: 0, unfilled: 0, accepted: 0, implemented: 1 });
    expect(it1.checkNodes).toEqual([]);
    expect(it1.nodes).toHaveLength(1);
    const na = threat('stride-web-global-ip-exposure-001', 'w', cs('not-applicable'));
    expect(item(evalWith([web], [na]), 'ipa-01').counts.implemented).toBe(0);
    expect(item(evalWith([web], [na]), 'ipa-01').nodes).toEqual([]);
    for (const s of ['required', 'rejected'] as const) {
      const t = threat('stride-web-global-ip-exposure-001', 'w', cs(s));
      expect(item(evalWith([web], [t]), 'ipa-01').status).toBe('action');
    }
  });

  it('手動脅威と、ruleIds に無いルールの検出は数えない', () => {
    const manual = threat('stride-web-global-ip-exposure-001', 'w', { origin: 'manual' });
    const other = threat('some-other-rule-001', 'w');
    expect(item(evalWith([web], [manual, other]), 'ipa-01').status).toBe('ok');
  });

  it('canonicalId で畳み込まれた脅威も元のルール id で照合する', () => {
    const merged = threat('other-rule-001', 'w', {
      id: 'canon::node:w',
      corroboration: {
        ruleIds: ['other-rule-001-w', 'stride-web-global-ip-exposure-001-w'],
        frameworks: ['STRIDE'],
      },
    });
    expect(item(evalWith([web], [merged]), 'ipa-01').status).toBe('action');
  });

  it('同じノードの複数検出は関係ノードを 1 つにまとめ、件数は検出数', () => {
    const r = evalWith(
      [web],
      [threat('stride-web-global-ip-exposure-001', 'w'), threat('webserver-webshell-implant-001', 'w')],
    );
    expect(item(r, 'ipa-01').nodes).toHaveLength(1);
    expect(item(r, 'ipa-01').counts.action).toBe(2);
  });

  it('集計は 17 項目の合計になる', () => {
    const r = evalWith([web], []);
    const total = Object.values(r.summary).reduce((a, b) => a + b, 0);
    expect(total).toBe(17);
  });
});

describe('点検が古い・未記録のノード', () => {
  const posture = (lastReviewedAt?: string) => ({ lastReviewedAt }) as DiagramNode['posture'];

  it('未設定は未記録、30 日ちょうどは古くない、31 日は古い', () => {
    const nodes = [
      n('a', 'FRONT_END_SERVER', 1),
      n('b', 'FRONT_END_SERVER', 2, { posture: posture('2026-09-10') }), // 30 日前
      n('c', 'FRONT_END_SERVER', 3, { posture: posture('2026-09-09') }), // 31 日前
      n('d', 'FRONT_END_SERVER', 4, { posture: posture('2026-10-09') }),
    ];
    const r = evalWith(nodes, []);
    expect(r.staleNodes.map((s) => [s.node.id, s.reason])).toEqual([
      ['a', 'unrecorded'],
      ['c', 'stale'],
    ]);
    expect(r.staleNodes[1].daysSince).toBe(31);
    expect(r.staleNodes[1].lastReviewedAt).toBe('2026-09-09');
  });

  it('不正な日付は未記録、未来の日付は古くない', () => {
    const nodes = [
      n('a', 'FRONT_END_SERVER', 1, { posture: posture('2026-02-30') }),
      n('b', 'FRONT_END_SERVER', 2, { posture: posture('yesterday') }),
      n('c', 'FRONT_END_SERVER', 3, { posture: posture('2027-01-01') }),
    ];
    const r = evalWith(nodes, []);
    expect(r.staleNodes.map((s) => s.node.id)).toEqual(['a', 'b']);
    expect(r.staleNodes.every((s) => s.reason === 'unrecorded')).toBe(true);
  });

  it('チェックリストの対象に無い型のノードは一覧に出さない', () => {
    const r = evalWith([n('u', 'USER', 1), n('x', 'CDN', 2)], []);
    expect(r.staleNodes).toEqual([]);
  });

  it('asOf は Date でも渡せる（UTC の日付で見る）', () => {
    const nodes = [n('c', 'FRONT_END_SERVER', 1, { posture: { lastReviewedAt: '2026-09-09' } })];
    const r = evalWith(nodes, [], new Date('2026-10-10T12:00:00Z'));
    expect(r.asOf).toBe('2026-10-10');
    expect(r.staleNodes).toHaveLength(1);
  });
});

describe('実エンジンとの結合', () => {
  const nodes: DiagramNode[] = [
    n('user', 'USER', 1),
    n('web', 'FRONT_END_SERVER', 2, { label: '公開 Web' }),
    n('db', 'DATABASE', 3),
  ];
  const edges: DiagramEdge[] = [
    { id: 'e1', source: 'user', target: 'web', auth: 'None', network: 'Internet', encryption: 'Plain' },
    { id: 'e2', source: 'web', target: 'db', auth: 'None', network: 'VPC', encryption: 'TLS' },
  ];
  const rules = getThreatLibrary('ja').rules;
  const views = buildThreatViews({
    detected: detectThreats({ nodes, edges, framework: 'ALL', rules }),
    manualThreats: [],
    nodes,
    framework: 'ALL',
    suppressions: {},
  });

  it('公開 Web の未入力は「未入力」、平文の線は項目 17 を要対応にしない（DB 側の暗号化は別ルール）', () => {
    const r = evaluateChecklist({ checklist: IPA, nodes, threats: views, asOf: ASOF });
    const flat = r.groups.flatMap((g) => g.items);
    expect(flat.some((i) => i.status === 'action' || i.status === 'unfilled')).toBe(true);
    expect(flat.find((i) => i.item.id === 'ipa-14')!.status).not.toBe('notApplicable');
    expect(flat.find((i) => i.item.id === 'ipa-08')!.status).toBe('notApplicable'); // SaaS / VPN が無い
  });
});

describe('出力', () => {
  const nodes = [n('w', 'FRONT_END_SERVER', 3, { label: '公開 | Web' })];
  const result = evalWith(nodes, [threat('webserver-webshell-implant-001', 'w')]);
  const project = { ...EMPTY_PROJECT_META, name: 'P1', systemName: 'Sys' };

  it('CSV：メタ → 表（項目単位）→ 点検が古いノード。ja/en の見出し', () => {
    const ja = toChecklistCsv({ result, project, layer: 'L1', locale: 'ja' });
    const lines = ja.split('\r\n');
    expect(lines[0]).toBe('スキーマバージョン,1');
    expect(lines[1]).toBe('kind,cyberriskscape-checklist-report');
    expect(ja).toContain('グループ,項目 No,項目,状態');
    expect(ja).toContain('ipa-01');
    expect(ja).toContain('要対応');
    expect(ja).toContain('点検が古い・未記録のノード');
    expect(ja).toContain('C3 公開 | Web,未記録');
    expect(ja).toContain('状態,要対応（脅威検出数）,未入力（脅威検出数）,リスク受容（脅威検出数）,対策済み（脅威検出数）,確かめ方,確認が必要なノード,確認が必要な脅威');
    const row = lines.find((l) => l.includes(',ipa-01,'))!;
    expect(row).toMatch(/,C3 公開 \| Web,.+（C3 公開 \| Web・要対応）$/);
    expect(ja).not.toContain('webserver-webshell-implant-001');
    const en = toChecklistCsv({ result, project, layer: 'L1', locale: 'en' });
    expect(en).toContain('Group,Item No,Item,Status');
    expect(en).toContain('Action needed');
  });

  it('Markdown：セル内の | をエスケープする', () => {
    const md = toChecklistMarkdown({ result, project, layer: 'L1', locale: 'ja' });
    expect(md).toContain('# IPA 注意喚起');
    expect(md).toContain('C3 公開 \\| Web');
    expect(md).toContain('判定は構成図に基づく');
  });

  it('JSON：状態は言語に依存しないコード', () => {
    const json = toChecklistJson({ result, project, layer: 'L1', locale: 'en' }) as {
      groups: { items: { id: string; status: string }[] }[];
      summary: Record<string, number>;
    };
    expect(json.groups[0].items.find((i) => i.id === 'ipa-01')!.status).toBe('action');
    expect(json.summary.action).toBeGreaterThan(0);
  });
});
