import { translate, type Locale, type TranslationKey } from '../../i18n';
import { componentRegistry } from '../../component-library/defaultRegistry';
import type { AppliesTo, AttackSurfaceMatch } from '../../threat-library/schema/threatRule';

/**
 * `appliesTo`（ルールの発火条件）を人間可読な日本語（またはロケール別）の説明文に
 * 変換する純関数。React 非依存。ThreatCard の「検出根拠」セクションで使う。
 *
 * 型名・属性名・列挙値そのものは翻訳せず `{...}` プレースホルダで補間する
 * （ノード型のみ `componentRegistry` の表示名解決を行う。ThreatCard.tsx と同じパターン）。
 */

type EdgeWhenLike = Record<string, unknown>;

/** ノード型 ID を表示名へ解決する（ThreatCard.tsx と同じパターン）。 */
function resolveTypeLabel(type: string): string {
  return componentRegistry.get(type)?.label ?? type;
}

function formatTypeList(types: readonly string[]): string {
  return types.map(resolveTypeLabel).join(' または ');
}

/**
 * `appliesTo` の条件フィールド名（`hasGlobalIp` / `auth` 等）を日本語ラベルへ解決する
 * 辞書。値（true/false/None/Internet 等の列挙値）は翻訳対象外——フィールド名のみを
 * 日本語化する。未収録キーはフォールバックとして元のキー名をそのまま使う
 * （将来のスキーマ拡張への耐性）。library-inspector のミニ図でも再利用する。
 */
const FIELD_LABEL_KEYS: Record<string, TranslationKey> = {
  hasGlobalIp: 'appliesToSummary.field.hasGlobalIp',
  hasSourceIpRestriction: 'appliesToSummary.field.hasSourceIpRestriction',
  hasRemoteAccessRestriction: 'appliesToSummary.field.hasRemoteAccessRestriction',
  hasUserAuthentication: 'appliesToSummary.field.hasUserAuthentication',
  hasAccessLog: 'appliesToSummary.field.hasAccessLog',
  hasWafProtection: 'appliesToSummary.field.hasWafProtection',
  hasDdosProtection: 'appliesToSummary.field.hasDdosProtection',
  auth: 'appliesToSummary.field.auth',
  network: 'appliesToSummary.field.network',
  encryption: 'appliesToSummary.field.encryption',
  sourceType: 'appliesToSummary.field.sourceType',
  targetType: 'appliesToSummary.field.targetType',
  sourceTrust: 'appliesToSummary.field.sourceTrust',
  targetTrust: 'appliesToSummary.field.targetTrust',
  sourceManagedState: 'appliesToSummary.field.sourceManagedState',
  targetManagedState: 'appliesToSummary.field.targetManagedState',
  sourceUserTrust: 'appliesToSummary.field.sourceUserTrust',
  targetUserTrust: 'appliesToSummary.field.targetUserTrust',
  semantic: 'appliesToSummary.field.semantic',
  agency: 'appliesToSummary.field.agency',
  blastRadius: 'appliesToSummary.field.blastRadius',
  identityTier: 'appliesToSummary.field.identityTier',
};

/** フィールド名を日本語ラベルへ解決する。未収録キーは元のキー名をそのまま返す。 */
export function resolveFieldLabel(field: string, locale: Locale): string {
  const key = FIELD_LABEL_KEYS[field];
  return key ? translate(key, locale) : field;
}

/** boolean マップ（AttackSurfaceMatch）を `ラベル=value` の列挙文字列にする。 */
function formatBooleanMap(match: AttackSurfaceMatch, locale: Locale): string {
  return Object.entries(match)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `${resolveFieldLabel(k, locale)}=${String(v)}`)
    .join('、');
}

/** 配列値マップ（AgentAttributesMatch / EdgeWhen）を `ラベル=v1/v2` の列挙文字列にする。 */
function formatArrayMap(match: EdgeWhenLike, locale: Locale, typeKeys: readonly string[] = []): string {
  return Object.entries(match)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => {
      const values = v as string[];
      const rendered = typeKeys.includes(k) ? values.map(resolveTypeLabel) : values;
      return `${resolveFieldLabel(k, locale)}=${rendered.join('/')}`;
    })
    .join('、');
}

const EDGE_WHEN_TYPE_KEYS = ['sourceType', 'targetType'];

function formatEdgeWhen(leaf: EdgeWhenLike, locale: Locale): string {
  return formatArrayMap(leaf, locale, EDGE_WHEN_TYPE_KEYS);
}

function summarizeConnection(
  appliesTo: Extract<AppliesTo, { kind: 'node' }>,
  locale: Locale,
): string {
  const conn = appliesTo.connection;
  const parts: string[] = [];

  if (!conn) {
    parts.push(translate('appliesToSummary.node.connection.default', locale));
  } else if (conn.required === false) {
    parts.push(translate('appliesToSummary.node.connection.intrinsic', locale));
  } else {
    const direction = conn.direction ?? 'any';
    if (direction === 'inbound') {
      parts.push(translate('appliesToSummary.node.connection.inbound', locale));
    } else if (direction === 'outbound') {
      parts.push(translate('appliesToSummary.node.connection.outbound', locale));
    } else {
      parts.push(translate('appliesToSummary.node.connection.default', locale));
    }
    if (conn.peerType) {
      parts.push(
        translate('appliesToSummary.node.connection.peerType', locale, {
          types: formatTypeList(conn.peerType),
        }),
      );
    }
    if (conn.peerAttackSurface) {
      parts.push(
        translate('appliesToSummary.node.connection.peerAttackSurface', locale, {
          conditions: formatBooleanMap(conn.peerAttackSurface, locale),
        }),
      );
    }
  }

  return parts.join('');
}

function summarizeNode(appliesTo: Extract<AppliesTo, { kind: 'node' }>, locale: Locale): string {
  const parts: string[] = [];

  if (appliesTo.nodeType) {
    parts.push(
      translate('appliesToSummary.node.target.single', locale, {
        type: resolveTypeLabel(appliesTo.nodeType),
      }),
    );
  } else if (appliesTo.anyOf) {
    parts.push(
      translate('appliesToSummary.node.target.anyOf', locale, {
        types: appliesTo.anyOf.map((leaf) => resolveTypeLabel(leaf.nodeType)).join(' または '),
      }),
    );
  }

  parts.push(summarizeConnection(appliesTo, locale));

  if (appliesTo.attackSurface) {
    parts.push(
      translate('appliesToSummary.node.attackSurface', locale, {
        conditions: formatBooleanMap(appliesTo.attackSurface, locale),
      }),
    );
  }

  if (appliesTo.agentAttributes) {
    parts.push(
      translate('appliesToSummary.node.agentAttributes', locale, {
        conditions: formatArrayMap(appliesTo.agentAttributes as unknown as EdgeWhenLike, locale),
      }),
    );
  }

  return parts.join('');
}

function summarizeEdge(appliesTo: Extract<AppliesTo, { kind: 'edge' }>, locale: Locale): string {
  if (appliesTo.when) {
    return translate('appliesToSummary.edge.when', locale, {
      conditions: formatEdgeWhen(appliesTo.when, locale),
    });
  }
  if (appliesTo.allOf) {
    return translate('appliesToSummary.edge.allOf', locale, {
      groups: appliesTo.allOf.map((leaf) => formatEdgeWhen(leaf, locale)).join('、かつ '),
    });
  }
  if (appliesTo.anyOf) {
    return translate('appliesToSummary.edge.anyOf', locale, {
      groups: appliesTo.anyOf.map((leaf) => formatEdgeWhen(leaf, locale)).join('、または '),
    });
  }
  return '';
}

/** `appliesTo` を発火条件の説明文へ変換する。 */
export function summarizeAppliesTo(appliesTo: AppliesTo, locale: Locale): string {
  return appliesTo.kind === 'node' ? summarizeNode(appliesTo, locale) : summarizeEdge(appliesTo, locale);
}
