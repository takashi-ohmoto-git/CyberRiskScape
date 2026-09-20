import type { DiagramEdge, DiagramNode } from '../model/types';
import { getNodeDisplayName } from '../model/nodeDisplay';
import { getComponentRegistry } from '../../component-library/defaultRegistry';
import { getLocale, translate } from '../../i18n';

// 型ラベルは現在の locale で解決する（`getNodeDisplayName` と同じ方針）。
function getTypeLabel(typeId: string): string {
  return getComponentRegistry(getLocale()).get(typeId)?.label ?? typeId;
}

/**
 * 説明文テンプレに含まれる `{{token}}` を展開する。
 *
 * 設計方針：
 * - 置換対象は固定トークン集合のみ。式評価や任意 JS は許さない（YAML は信頼境界外）。
 * - 未知トークンは原文のまま残す（テンプレ記法の typo を握りつぶさないため）。
 * - ルール側からノードオブジェクトに直接触れないよう、ここで一段抽象化する。
 */

export type TemplateContext =
  | {
      kind: 'node';
      node: DiagramNode;
      /**
       * この発行元に依存するコンポーネント（[[plan]] §2.40 Tier 1）。
       * `{{dependentCount}}` / `{{dependentNames}}` の展開に使う。省略時は依存ゼロ扱い。
       */
      dependents?: readonly DiagramNode[];
    }
  | { kind: 'edge'; source: DiagramNode; target: DiagramNode };

const TOKEN_RE = /\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}/g;

function resolveToken(token: string, ctx: TemplateContext): string | undefined {
  if (ctx.kind === 'node') {
    switch (token) {
      case 'nodeName':
        return getNodeDisplayName(ctx.node);
      case 'nodeType':
        return getTypeLabel(ctx.node.type);
      case 'dependentCount':
        // 依存ゼロでも "0" を返す。トークンを原文のまま残すと文が壊れるため。
        return String(ctx.dependents?.length ?? 0);
      case 'dependentNames': {
        const names = (ctx.dependents ?? []).map(getNodeDisplayName);
        // 依存ゼロのときは列挙が空になり「（）」のような文になるため、明示的な語を返す。
        return names.length > 0
          ? names.join(translate('threat.template.nameSeparator', getLocale()))
          : translate('threat.template.noDependents', getLocale());
      }
      default:
        return undefined;
    }
  }
  switch (token) {
    case 'sourceName':
      return getNodeDisplayName(ctx.source);
    case 'targetName':
      return getNodeDisplayName(ctx.target);
    case 'sourceType':
      return getTypeLabel(ctx.source.type);
    case 'targetType':
      return getTypeLabel(ctx.target.type);
    default:
      return undefined;
  }
}

export function renderTemplate(template: string, ctx: TemplateContext): string {
  return template.replace(TOKEN_RE, (match, token: string) => {
    const value = resolveToken(token, ctx);
    return value !== undefined ? value : match;
  });
}

/** edge ルール向けの便宜関数（呼び出し側を読みやすくするだけ）。 */
export function renderEdgeTemplate(
  template: string,
  source: DiagramNode,
  target: DiagramNode,
): string {
  return renderTemplate(template, { kind: 'edge', source, target });
}

/**
 * node ルール向けの便宜関数。
 * `dependents`（[[plan]] §2.40）は任意。渡さない呼び出しは依存ゼロとして展開される。
 */
export function renderNodeTemplate(
  template: string,
  node: DiagramNode,
  dependents?: readonly DiagramNode[],
): string {
  return renderTemplate(template, { kind: 'node', node, dependents });
}

// edge は将来別のメタに直接触れる可能性に備えて受け取れるよう公開する。
export type { DiagramEdge };
