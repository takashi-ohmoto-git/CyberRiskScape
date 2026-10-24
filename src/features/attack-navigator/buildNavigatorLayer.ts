import { isSuppressed, type ProjectMeta, type Severity, type ThreatView } from '../../core/model/types';
import { effectiveSeverity } from '../../core/model/risk';
import { BRANDING } from '../../core/branding';
import { getLocale, translate, type Locale } from '../../i18n';

/**
 * 脅威モデルの検出脅威から、MITRE ATT&CK Navigator レイヤー（JSON）を組み立てる純粋関数。
 *
 * 狙い：CTEM / BAS / SOC のツールが取り込める「標準の拡張」に載せる（独自形式を発明しない）。
 * 各脅威ルールの references に書かれた ATT&CK / ATLAS の technique へのリンク・表記から ID を取り出し、
 * ATT&CK Enterprise の technique を Navigator レイヤーとして出す。ATLAS（AML.T*）は Enterprise の行列に
 * 無いため、レイヤーの説明文に一覧として添える（ATLAS Navigator は別物のため混ぜない）。
 *
 * 限界：technique ID は references の自由記述（title / url）から取り出す。ルールが references を持たない、
 * または ATT&CK/ATLAS 以外を参照している場合は拾えない。network/あて先の強制と同じく、カバレッジの網羅は
 * 保証しない（図と脅威ライブラリの参照の質に依存する）。
 */

/** ATT&CK Enterprise technique ID（例: T1078 / T1078.004）。 */
const ATTACK_RE = /\bT\d{4}(?:\.\d{3})?\b/g;
/** ATLAS technique ID（例: AML.T0051 / AML.T0052.001）。 */
const ATLAS_RE = /\bAML\.T\d{4}(?:\.\d{3})?\b/g;

const SCORE_BY_SEVERITY: Record<Severity, number> = {
  Low: 25,
  Medium: 50,
  High: 75,
  Critical: 100,
};

const SEV_RANK: Record<Severity, number> = { Low: 1, Medium: 2, High: 3, Critical: 4 };

export interface NavigatorTechnique {
  techniqueID: string;
  score: number;
  color: string;
  comment: string;
  enabled: boolean;
}

/** MITRE ATT&CK Navigator レイヤー（schema layer v4.5 の必要部分）。 */
export interface NavigatorLayer {
  name: string;
  versions: { attack: string; navigator: string; layer: string };
  domain: 'enterprise-attack';
  description: string;
  techniques: NavigatorTechnique[];
  gradient: { colors: string[]; minValue: number; maxValue: number };
  /** ATLAS（AML.T*）の technique ID。Enterprise 行列に無いため参考として分離して持つ。 */
  atlasTechniques: string[];
}

export interface NavigatorInput {
  threats: ThreatView[];
  projectMeta: ProjectMeta;
}

function colorForScore(score: number): string {
  if (score >= 100) return '#b10026'; // Critical
  if (score >= 75) return '#e3211c'; // High
  if (score >= 50) return '#fc8d59'; // Medium
  return '#fee08b'; // Low
}

function extract(re: RegExp, text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(re)) out.push(m[0]);
  return out;
}

export function buildNavigatorLayer(
  input: NavigatorInput,
  now: Date,
  locale: Locale = getLocale(),
): NavigatorLayer {
  const t = (key: string, params?: Record<string, string | number>) =>
    translate(key as Parameters<typeof translate>[0], locale, params);

  // technique ID → { maxSeverity, 脅威名の集合 }
  const attack = new Map<string, { sev: Severity; names: Set<string> }>();
  const atlas = new Set<string>();

  for (const threat of input.threats) {
    if (isSuppressed(threat)) continue;
    const refs = threat.references ?? [];
    if (refs.length === 0) continue;
    const text = refs.map((r) => `${r.title} ${r.url ?? ''}`).join(' ');
    const sev = effectiveSeverity(threat);
    const name = threat.name ?? threat.category;

    for (const id of extract(ATLAS_RE, text)) atlas.add(id);
    // ATLAS を先に拾って取り除く（AML.T0051 の "T0051" を ATT&CK と誤認しないため）
    const attackText = text.replace(ATLAS_RE, ' ');
    for (const id of extract(ATTACK_RE, attackText)) {
      const cur = attack.get(id);
      if (!cur) {
        attack.set(id, { sev, names: new Set([name]) });
      } else {
        if (SEV_RANK[sev] > SEV_RANK[cur.sev]) cur.sev = sev;
        cur.names.add(name);
      }
    }
  }

  const techniques: NavigatorTechnique[] = [...attack.entries()]
    .map(([techniqueID, { sev, names }]) => {
      const score = SCORE_BY_SEVERITY[sev];
      return {
        techniqueID,
        score,
        color: colorForScore(score),
        comment: [...names].join('; '),
        enabled: true,
      };
    })
    .sort((a, b) => b.score - a.score || a.techniqueID.localeCompare(b.techniqueID));

  const system = input.projectMeta.systemName.trim() || input.projectMeta.name.trim() || BRANDING.name;
  const date = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
  const atlasTechniques = [...atlas].sort();
  const atlasNote =
    atlasTechniques.length > 0 ? ` ${t('navigator.description.atlas', { ids: atlasTechniques.join(', ') })}` : '';

  return {
    name: t('navigator.layerName', { system }),
    versions: { attack: '15', navigator: '4.9.0', layer: '4.5' },
    domain: 'enterprise-attack',
    description: `${t('navigator.description.main', { system, product: BRANDING.name, date })}${atlasNote}`,
    techniques,
    gradient: { colors: ['#fee08b', '#fc8d59', '#e3211c', '#b10026'], minValue: 25, maxValue: 100 },
    atlasTechniques,
  };
}

export function navigatorLayerToJson(layer: NavigatorLayer): string {
  // atlasTechniques は Navigator の標準フィールドではないので JSON 出力からは外し、説明文に残す。
  const { atlasTechniques: _atlas, ...standard } = layer;
  void _atlas;
  return JSON.stringify(standard, null, 2);
}
