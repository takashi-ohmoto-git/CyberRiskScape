import type { AuthType, EncryptionType, NetworkType } from '../model/types';
import type { TranslationKey } from '../../i18n';

/**
 * エッジ（データフロー）の視覚記法を **単一の宣言** に集約するモジュール。
 *
 * 描画（`EdgeLayer`）と凡例（`Legend`）はここを唯一の真実ソースとして参照する。
 * 「記法ルールを描画コードに散在させない」方針（CLAUDE.md の脅威知識非埋込と同思想）。
 * 新しい線記法を足すときは、ここを変えれば描画と凡例が同時に追従する。
 */

/**
 * 矢印マーカー／線の stroke 色。リスク状態・選択状態で切り替える。
 * SVG marker の塗りは line の stroke を継承できないため、色ごとに別 marker を用意する
 * （描画側はこのキーで `arrow-{key}` を引く）。
 */
export const EDGE_STROKE_COLORS = {
  normal: '#475569',
  selected: '#3b82f6',
  risk: '#ef4444',
} as const;

export type EdgeStrokeKey = keyof typeof EDGE_STROKE_COLORS;

/**
 * 暗号化区分 → 線の `strokeDasharray`。`'0'` は実線。
 * 現状は平文のみ破線で強調し、TLS / E2EE は実線（区別は凡例とパネル属性で表現）。
 */
export const ENCRYPTION_DASH: Record<EncryptionType, string> = {
  Plain: '6,4',
  TLS: '0',
  E2EE: '0',
};

/**
 * 高リスク経路（未認証 × Internet）の判定。該当エッジは赤線で強調する記法ルール。
 * `EdgeLayer` のマーカー色選択と凡例の表示要否がこの 1 関数を共有する。
 */
export function isHighRiskEdge(edge: { auth: AuthType; network: NetworkType }): boolean {
  return edge.auth === 'None' && edge.network === 'Internet';
}

/**
 * 凡例に出す線記法の 1 エントリ。`appliesTo` は「図中にこの記法が実在するか」の判定に使い、
 * 使っている記号だけを凡例化する（未使用記法でノイズを増やさない）。
 */
export interface EdgeNotationLegendEntry {
  id: string;
  labelKey: TranslationKey;
  /** 凡例スウォッチの描画ヒント（線の dash と色）。 */
  swatch: { dash: string; stroke: string };
  appliesTo: (edge: { auth: AuthType; network: NetworkType; encryption: EncryptionType }) => boolean;
}

/**
 * 線記法の凡例カタログ。描画側の合成規則（色＝リスク、dash＝暗号化）と一致させる。
 * 暗号化（平文／暗号化あり）とリスク（高リスク経路）は直交する軸なので別エントリで提示する。
 */
export const EDGE_NOTATION_LEGEND: readonly EdgeNotationLegendEntry[] = [
  {
    id: 'plain',
    labelKey: 'canvas.edgeNotation.plain',
    swatch: { dash: ENCRYPTION_DASH.Plain, stroke: EDGE_STROKE_COLORS.normal },
    appliesTo: (e) => e.encryption === 'Plain',
  },
  {
    id: 'encrypted',
    labelKey: 'canvas.edgeNotation.encrypted',
    swatch: { dash: '0', stroke: EDGE_STROKE_COLORS.normal },
    appliesTo: (e) => e.encryption !== 'Plain',
  },
  {
    id: 'high-risk',
    labelKey: 'canvas.edgeNotation.highRisk',
    swatch: { dash: '0', stroke: EDGE_STROKE_COLORS.risk },
    appliesTo: isHighRiskEdge,
  },
];

/**
 * 信頼境界クロッシングマーカーの寸法（[[plan]] §2.39 A-1）。
 * 境界の矩形と経路の交点に、経路へ直交する**単線を 1 本**だけ引く。
 */
export const CROSSING_MARK = {
  /** 経路に直交する線分の長さ。 */
  length: 20,
  strokeWidth: 3,
} as const;

/**
 * `auth` → クロッシングマーカーの色（赤＝無認証 / 黄＝パスワード / 緑＝MFA の信号色）。
 *
 * 黄は amber ではなく yellow-500 を使う。Partner 境界の枠線（orange-500）と紛れないようにするため。
 * 境界の `trustLevel` は矩形の枠線色とラベルが既に示しているので、マーカーは認証の軸だけを担う。
 */
export const CROSSING_AUTH_COLORS: Record<AuthType, string> = {
  None: '#ef4444',
  Password: '#eab308',
  MFA: '#10b981',
};

/** クロッシング凡例の `auth` 行。図に実在する `auth` 値の行だけを出す。 */
export const CROSSING_AUTH_LEGEND: readonly { auth: AuthType; labelKey: TranslationKey }[] = [
  { auth: 'None', labelKey: 'canvas.edgeNotation.crossingAuthNone' },
  { auth: 'Password', labelKey: 'canvas.edgeNotation.crossingAuthPassword' },
  { auth: 'MFA', labelKey: 'canvas.edgeNotation.crossingAuthMfa' },
];
