import { effectiveSeverity } from '../../core/model/risk';
import { buildAttackGraph } from '../attack-tree/buildAttackGraph';
import { buildEntryEdges, ENTRY_SEARCH_APPLICABLE, findEntryPoints } from '../attack-tree/findEntryPoints';
import type { LayerContext } from '../attack-tree/prioritizeFindings';
import { recommendTargets } from '../attack-tree/recommendTargets';
import { BUNDLED_INDICATOR_WEIGHTS, type IndicatorWeights } from './computeIndicators';

/**
 * 重要資産に届く攻撃経路上の未対策の脅威（docs/org-view.md §4.1）。
 * 「CVE が何件残っているか」ではなく「攻撃者がどの経路で重要資産に届くか」を数字にする。
 *
 * - 重要資産：攻撃者から到達できる推奨標的（`recommendTargets`：認証基盤・機微データ・業務の重要度 High）
 * - 経路：攻撃者 → 標的の経路（`buildAttackGraph`。侵入候補の仮想の線を含む）。標的自身も経路に含む
 * - ノードの脅威は、内包する資産を親に寄せたノードが経路上にあるとき、線の脅威は、その線が経路のホップに
 *   含まれるとき数える
 * - 未対策：対策実装状況が「実装済み」でない。誤検知・適用外は数えない（既存の 3 指標と同じ）。受容は残す
 *
 * 攻撃者（AI エージェント型の攻撃者のノード）がどのレイヤーにも無ければ null（評価できない）。
 * 既存の「総合」には入れない（あちらは検討の進捗の割合、こちらは残っている露出の件数）。
 */
export interface AttackPathExposure {
  /** 攻撃者から到達できる推奨標的の数。 */
  targets: number;
  /** 経路上に未対策の脅威がある標的の数。 */
  exposedTargets: number;
  /** 経路上の脅威（誤検知・適用外を除く）の件数。 */
  onPath: number;
  /** そのうち未対策の件数。 */
  open: number;
  /** 未対策の脅威の重み付きの値（重大度の重みの合計。リスク評価があれば評価後の重大度）。 */
  openWeighted: number;
  /** 経路の列挙が上限に達したレイヤーがある（数え漏れがありうる）。 */
  truncated: boolean;
  /** この結果の計算に使った重み。 */
  weights: IndicatorWeights;
}

export function computeAttackPathExposure(
  layers: readonly LayerContext[],
  weights: IndicatorWeights = BUNDLED_INDICATOR_WEIGHTS,
): AttackPathExposure | null {
  let evaluated = false;
  const result = { targets: 0, exposedTargets: 0, onPath: 0, open: 0, openWeighted: 0, truncated: false };

  for (const ctx of layers) {
    const attacker = ctx.nodes.find((n) => ENTRY_SEARCH_APPLICABLE.has(n.type))?.id;
    if (!attacker) continue;
    evaluated = true;

    const ids = new Set(ctx.nodes.map((n) => n.id));
    const topOf = (id: string) => {
      const p = ctx.nodes.find((n) => n.id === id)?.parentId;
      return p && ids.has(p) ? p : id;
    };
    const entries = findEntryPoints(ctx.nodes, ctx.edges, ctx.boundaries, ctx.threats, attacker);
    const analysisEdges = [...ctx.edges, ...buildEntryEdges(attacker, entries)];
    const targets = recommendTargets(ctx.nodes, ctx.edges, ctx.boundaries, ctx.threats, attacker).filter(
      (t) => t.reachable,
    );

    const counted = (t: LayerContext['threats'][number]) =>
      t.suppression?.status !== 'false-positive' && t.controlStatus?.status !== 'not-applicable';
    const isOpen = (t: LayerContext['threats'][number]) => t.controlStatus?.status !== 'implemented';
    const onLayerPath = new Set<LayerContext['threats'][number]>();

    for (const target of targets) {
      const g = buildAttackGraph(ctx.nodes, analysisEdges, attacker, target.nodeId);
      if (g.truncated) result.truncated = true;
      const routeNodes = new Set(g.nodeIds.filter((id) => id !== attacker));
      routeNodes.add(target.nodeId);
      const routeEdges = new Set<string>();
      for (const hop of g.hops.values()) for (const e of hop.edgeIds) routeEdges.add(e);

      let exposed = false;
      for (const t of ctx.threats) {
        if (!counted(t)) continue;
        const onRoute = t.subject?.kind === 'edge' ? routeEdges.has(t.subject.id) : routeNodes.has(topOf(t.nodeId));
        if (!onRoute) continue;
        onLayerPath.add(t);
        if (isOpen(t)) exposed = true;
      }
      result.targets += 1;
      if (exposed) result.exposedTargets += 1;
    }

    for (const t of onLayerPath) {
      result.onPath += 1;
      if (isOpen(t)) {
        result.open += 1;
        result.openWeighted += weights.severity[effectiveSeverity(t)];
      }
    }
  }

  return evaluated ? { ...result, weights } : null;
}
