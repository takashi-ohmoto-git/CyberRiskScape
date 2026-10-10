import type { z } from 'zod';
import type {
  DiagramBoundary,
  DiagramNode,
  MicroSegmentationStatus,
  SensitiveData,
} from '../model/types';
import type {
  SegmentRelationSchema,
  SegmentSensitiveDataSchema,
  SegmentStatusSchema,
} from '../../threat-library/schema/threatRule';
import { resolveDrawableAncestor } from '../model/parentChain';
import { getNodeCenter } from '../canvas/nodeGeometry';

type SegmentStatus = z.infer<typeof SegmentStatusSchema>;
type SegmentSensitiveData = z.infer<typeof SegmentSensitiveDataSchema>;
type SegmentRelation = z.infer<typeof SegmentRelationSchema>;

/** ノードの所属区画（脅威ルールの `segment` 軸の評価対象）。 */
export interface ResolvedSegment {
  /** 所属する ROUNDED_DASHED の id。区画外なら undefined。 */
  boundaryId?: string;
  status: SegmentStatus;
  environment?: DiagramBoundary['microTrust'];
  sensitiveData?: SegmentSensitiveData;
}

/** 保存データの日本語値 → ルール側の英語値。 */
const STATUS_TO_RULE: Record<MicroSegmentationStatus, SegmentStatus> = {
  適用済み: 'Enforced',
  部分適用: 'PartiallyEnforced',
  未適用: 'NotEnforced',
};

const SENSITIVE_DATA_TO_RULE: Record<SensitiveData, SegmentSensitiveData> = {
  無し: 'None',
  個人情報: 'PersonalData',
  機密情報: 'Confidential',
};

export const UNSEGMENTED: ResolvedSegment = { status: 'Unsegmented' };

/**
 * 各ノードの所属区画を解決する。
 *
 * 仕様（`resolveNodeTrust` と同じ包含判定）：
 * - 対象は ROUNDED_DASHED（マイクロセグメンテーション）だけ。他の境界型は見ない。
 * - **ノード中心**を矩形に含む区画を所属とみなす。入れ子は**面積最小（最内側）**を採用。
 * - 内包ノード（parentId 持ち）は描画上の祖先の中心で判定する。
 * - 適用状態が未設定の区画（旧データ）は、新規作成時の既定と同じ `NotEnforced` とみなす。
 */
export function resolveNodeSegment(
  nodes: DiagramNode[],
  boundaries: DiagramBoundary[],
): Map<string, ResolvedSegment> {
  const map = new Map<string, ResolvedSegment>();
  const segments = boundaries.filter((b) => b.type === 'ROUNDED_DASHED');
  for (const node of nodes) {
    const anchor = getNodeCenter(resolveDrawableAncestor(node, nodes));
    let inner: DiagramBoundary | null = null;
    let innerArea = Infinity;
    for (const b of segments) {
      if (
        anchor.x >= b.x &&
        anchor.x <= b.x + b.width &&
        anchor.y >= b.y &&
        anchor.y <= b.y + b.height
      ) {
        const area = b.width * b.height;
        if (area < innerArea) {
          inner = b;
          innerArea = area;
        }
      }
    }
    map.set(
      node.id,
      inner
        ? {
            boundaryId: inner.id,
            status: STATUS_TO_RULE[inner.microSegmentationStatus ?? '未適用'],
            environment: inner.microTrust,
            sensitiveData: inner.sensitiveData && SENSITIVE_DATA_TO_RULE[inner.sensitiveData],
          }
        : UNSEGMENTED,
    );
  }
  return map;
}

/** エッジ両端の所属区画の関係。 */
export function segmentRelationOf(a: ResolvedSegment, b: ResolvedSegment): SegmentRelation {
  if (a.boundaryId === undefined && b.boundaryId === undefined) return 'None';
  return a.boundaryId === b.boundaryId ? 'Same' : 'Cross';
}
