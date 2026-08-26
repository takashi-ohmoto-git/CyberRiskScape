import type { DiagramEdge, DiagramNode } from '../model/types';
import { getNodeDisplayName } from '../model/nodeDisplay';
import { componentRegistry } from '../../component-library/defaultRegistry';

function getTypeLabel(typeId: string): string {
  return componentRegistry.get(typeId)?.label ?? typeId;
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
  | { kind: 'node'; node: DiagramNode }
  | { kind: 'edge'; source: DiagramNode; target: DiagramNode };

const TOKEN_RE = /\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}/g;

function resolveToken(token: string, ctx: TemplateContext): string | undefined {
  if (ctx.kind === 'node') {
    switch (token) {
      case 'nodeName':
        return getNodeDisplayName(ctx.node);
      case 'nodeType':
        return getTypeLabel(ctx.node.type);
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

/** node ルール向けの便宜関数。 */
export function renderNodeTemplate(template: string, node: DiagramNode): string {
  return renderTemplate(template, { kind: 'node', node });
}

// edge は将来別のメタに直接触れる可能性に備えて受け取れるよう公開する。
export type { DiagramEdge };
