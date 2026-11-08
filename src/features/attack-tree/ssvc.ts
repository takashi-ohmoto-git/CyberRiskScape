import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { CVSS_VECTOR_RE, type Finding, type Severity } from '../../core/model/types';

/**
 * CISA SSVC の判定（Track / Track* / Attend / Act）。判定表は `data/ssvc/cisa-ssvc.yaml`（出典はそのファイル冒頭）。
 * 指摘の文脈（露出・標的・KEV 等）から 4 つの判定点を決め、表で判定する。
 * 値が図から決まらないときは悪い側の仮定を置き、`assumed` で示す（Technical Impact は CVSS ベクターがあれば
 * `cvssTechnicalImpact` の規則で決め、無ければ深刻度から仮置き）。
 * 推奨であり判断は人（docs/attack-tree-analysis.md §12）。
 */

export const SSVC_EXPLOITATION = ['none', 'poc', 'active'] as const;
export const SSVC_AUTOMATABLE = ['no', 'yes'] as const;
export const SSVC_TECHNICAL_IMPACT = ['partial', 'total'] as const;
export const SSVC_MISSION = ['low', 'medium', 'high'] as const;
export const SSVC_DECISIONS = ['Track', 'Track*', 'Attend', 'Act'] as const;

export type SsvcDecision = (typeof SSVC_DECISIONS)[number];

export interface SsvcPoints {
  exploitation: (typeof SSVC_EXPLOITATION)[number];
  automatable: (typeof SSVC_AUTOMATABLE)[number];
  technicalImpact: (typeof SSVC_TECHNICAL_IMPACT)[number];
  missionWellbeing: (typeof SSVC_MISSION)[number];
}

const SsvcFileSchema = z.object({
  schemaVersion: z.literal(1),
  decisions: z.array(z.object({ id: z.enum(SSVC_DECISIONS), description: z.string().min(1) })),
  cvssTechnicalImpact: z.object({ total: z.array(z.string().regex(/^[A-Z]{1,3}:[A-Z]$/)).min(1) }),
  rows: z.array(
    z.object({
      exploitation: z.enum(SSVC_EXPLOITATION),
      automatable: z.enum(SSVC_AUTOMATABLE),
      technicalImpact: z.enum(SSVC_TECHNICAL_IMPACT),
      missionWellbeing: z.enum(SSVC_MISSION),
      decision: z.enum(SSVC_DECISIONS),
    }),
  ),
});

export interface SsvcTable {
  descriptions: Record<SsvcDecision, string>;
  rows: Map<string, SsvcDecision>;
  /** CVSS のこの指標値が 1 つでもあれば Technical Impact＝total。 */
  cvssTotal: ReadonlySet<string>;
}

const keyOf = (p: SsvcPoints) => `${p.exploitation}|${p.automatable}|${p.technicalImpact}|${p.missionWellbeing}`;

/** 判定表を読み込む。36 通りがちょうど 1 回ずつ、4 つの判定結果の説明がそろっていなければ例外。 */
export function loadSsvcTable(text: string): SsvcTable {
  const file = SsvcFileSchema.parse(parseYaml(text));
  const rows = new Map<string, SsvcDecision>();
  for (const r of file.rows) {
    const k = keyOf(r);
    if (rows.has(k)) throw new Error(`[ssvc] 判定点の組み合わせ ${k} が重複しています`);
    rows.set(k, r.decision);
  }
  const expected = SSVC_EXPLOITATION.length * SSVC_AUTOMATABLE.length * SSVC_TECHNICAL_IMPACT.length * SSVC_MISSION.length;
  if (rows.size !== expected) throw new Error(`[ssvc] 判定表は ${expected} 行が必要です（${rows.size} 行）`);
  const descriptions = {} as Record<SsvcDecision, string>;
  for (const d of file.decisions) descriptions[d.id] = d.description;
  for (const id of SSVC_DECISIONS) if (!descriptions[id]) throw new Error(`[ssvc] decisions に ${id} がありません`);
  return { descriptions, rows, cvssTotal: new Set(file.cvssTechnicalImpact.total) };
}

// ── 同梱データ（Vite の import.meta.glob で raw 文字列として取り込む。CLI ビルド・Vitest でも動く）──

const sources = import.meta.glob<string>('../../../data/ssvc/cisa-ssvc.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const BUNDLED_SSVC: SsvcTable = loadSsvcTable(Object.values(sources)[0] ?? '');

export function ssvcDecide(points: SsvcPoints, table: SsvcTable = BUNDLED_SSVC): SsvcDecision {
  const d = table.rows.get(keyOf(points));
  if (!d) throw new Error(`[ssvc] 判定表に ${keyOf(points)} がありません`);
  return d;
}

/**
 * CVSS ベクターから Technical Impact を決める。規則は判定表の `cvssTechnicalImpact`。
 * 受け付けない形のベクター（v2 等）は undefined（呼び出し側で深刻度から仮置きする）。
 */
export function technicalImpactFromCvss(
  vector: string | undefined,
  table: SsvcTable = BUNDLED_SSVC,
): { value: SsvcPoints['technicalImpact']; matched: string[] } | undefined {
  if (!vector || !CVSS_VECTOR_RE.test(vector)) return undefined;
  const matched = vector.split('/').slice(1).filter((m) => table.cvssTotal.has(m));
  return { value: matched.length > 0 ? 'total' : 'partial', matched };
}

/** 判定点ごとの「仮定」の印。 */
export interface SsvcAssumed {
  automatable: boolean;
  /** CVSS ベクターが無く、深刻度から仮置きしたとき true（人が確かめる）。 */
  technicalImpact: boolean;
  missionWellbeing: boolean;
}

export interface SsvcAssessment {
  decision: SsvcDecision;
  points: SsvcPoints;
  assumed: SsvcAssumed;
  /** 判定点ごとの根拠（日本語）。 */
  reasons: string[];
}

/** 判定点の決定に使う、指摘の文脈（PrioritizedFinding の一部）。 */
export interface SsvcInput {
  finding: Finding;
  exposure: 'entry' | 'reachable' | 'unreachable' | 'unbound' | 'unevaluated';
  exposureAssumed: boolean;
  reachesTargets: readonly unknown[];
  chainIndexes: readonly unknown[];
  /** この指摘のノード自身が推奨標的。 */
  isTarget: boolean;
}

const HIGH_SEVERITY: ReadonlySet<Severity> = new Set<Severity>(['Critical', 'High']);

/** 指摘の文脈から SSVC の判定点を決める。EPSS は使わない。 */
export function ssvcPointsFor(item: SsvcInput): SsvcAssessment {
  const { finding: f, exposure } = item;
  const reasons: string[] = [];

  let exploitation: SsvcPoints['exploitation'];
  if (f.kev) {
    exploitation = 'active';
    reasons.push('Exploitation=active：KEV の印がある');
  } else if (f.source.format === 'pentest' && f.outcome !== 'attempted' && f.outcome !== 'unverified') {
    exploitation = 'poc';
    reasons.push('Exploitation=poc：ペンテストで実証された指摘');
  } else {
    exploitation = 'none';
    reasons.push('Exploitation=none：KEV の印も実証もない（EPSS は使わない）');
  }

  let automatable: SsvcPoints['automatable'];
  let autoAssumed = item.exposureAssumed;
  if (exposure === 'entry') {
    automatable = 'yes';
    reasons.push('Automatable=yes：侵入口の候補にあるノード');
  } else if (exposure === 'reachable') {
    automatable = item.chainIndexes.length > 0 ? 'yes' : 'no';
    reasons.push(
      automatable === 'yes'
        ? 'Automatable=yes：入口の奥にあり、指摘が連なる連鎖に含まれる'
        : 'Automatable=no：入口の奥にあるが連鎖には含まれない',
    );
  } else if (exposure === 'unreachable') {
    automatable = 'no';
    reasons.push('Automatable=no：攻撃者から到達できない');
  } else {
    automatable = 'yes';
    autoAssumed = true;
    reasons.push('Automatable=yes（仮定）：露出を評価できないため悪い側に置く');
  }
  if (item.exposureAssumed) reasons.push('Automatable：入口・到達の判定が未入力の攻撃面属性の仮定に依存している');

  const fromCvss = technicalImpactFromCvss(f.cvss);
  const technicalImpact: SsvcPoints['technicalImpact'] = fromCvss?.value ?? (HIGH_SEVERITY.has(f.severity) ? 'total' : 'partial');
  if (fromCvss) {
    reasons.push(
      fromCvss.value === 'total'
        ? `Technical Impact=total：CVSS ベクターに ${fromCvss.matched.join('・')} がある`
        : 'Technical Impact=partial：CVSS ベクターで機密性・完全性の影響が High ではない',
    );
  } else {
    reasons.push(`Technical Impact=${technicalImpact}（仮置き）：CVSS ベクターが無いため深刻度 ${f.severity} から置いた。人が確かめる`);
  }

  let missionWellbeing: SsvcPoints['missionWellbeing'];
  let missionAssumed = false;
  if (exposure === 'unbound' || exposure === 'unevaluated') {
    missionWellbeing = 'high';
    missionAssumed = true;
    reasons.push('Mission & Well-being=high（仮定）：標的との関係を評価できないため悪い側に置く');
  } else if (item.isTarget) {
    missionWellbeing = 'high';
    reasons.push('Mission & Well-being=high：ノード自身が推奨標的');
  } else if (item.reachesTargets.length > 0) {
    missionWellbeing = 'medium';
    reasons.push('Mission & Well-being=medium：推奨標的に届く');
  } else {
    missionWellbeing = 'low';
    reasons.push('Mission & Well-being=low：推奨標的に届かない');
  }

  const points: SsvcPoints = { exploitation, automatable, technicalImpact, missionWellbeing };
  return {
    decision: ssvcDecide(points),
    points,
    assumed: { automatable: autoAssumed, technicalImpact: !fromCvss, missionWellbeing: missionAssumed },
    reasons,
  };
}
