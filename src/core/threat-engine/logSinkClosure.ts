import type { DiagramNode } from '../model/types';

/**
 * ログの送信先（`node.logSinkId`）の参照グラフ。`authProviderClosure.ts` のログ版で、
 * 新しいデータは持たず既存の参照からの派生ビュー。
 *
 * 送信先として参照されている SIEM は**論理的に接続されている**とみなす（図に線を引かなくても
 * ログが届く構成を表すため）。参照先が削除済み（dangling）／自己参照は数えない。
 */
export interface LogSinkClosure {
  /** 送信先ノード id → そのノードへログを送るノード。 */
  readonly sources: ReadonlyMap<string, DiagramNode[]>;
}

export function buildLogSinkClosure(nodes: readonly DiagramNode[]): LogSinkClosure {
  const nodeIds = new Set(nodes.map((n) => n.id));
  const sources = new Map<string, DiagramNode[]>();
  for (const node of nodes) {
    const sinkId = node.logSinkId;
    if (!sinkId || sinkId === node.id || !nodeIds.has(sinkId)) continue;
    const list = sources.get(sinkId);
    if (list) list.push(node);
    else sources.set(sinkId, [node]);
  }
  return { sources };
}

/** 送信先 X にログを送るノード。未登録なら空配列。 */
export function logSourcesOf(closure: LogSinkClosure, sinkId: string): DiagramNode[] {
  return closure.sources.get(sinkId) ?? [];
}

/** ノードが送信先として参照されている（＝**論理的に接続されている**）か。 */
export function isReferencedLogSink(closure: LogSinkClosure, nodeId: string): boolean {
  return closure.sources.has(nodeId);
}
