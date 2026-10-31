import { isSuppressed, type Severity, type ThreatView } from '../../core/model/types';
import { effectiveSeverity } from '../../core/model/risk';
import type { AttackGraphResult } from '../attack-tree/buildAttackGraph';
import type { AnalyzeGraphResult } from '../attack-tree/analyzeAttackGraph';
import { edgeElementKey, nodeElementKey } from '../attack-tree/hopEvidence';
import { extractAttackTechniqueIds, threatElementKey } from '../attack-navigator/buildNavigatorLayer';
import { ATTACK_MATRIX } from './attackMatrix';

/** test-plan・Navigator と同じ上位経路の本数。 */
const TOP_ROUTES = 3;

const SEV_RANK: Record<Severity, number> = { Low: 1, Medium: 2, High: 3, Critical: 4 };

export interface TechniqueHit {
  threatId: string;
  threatName: string;
  /** `node:<id>` / `edge:<id>`。経路外で検出された脅威は境界など null になり得る。 */
  elementKey: string | null;
  /** この要素が経路上で何歩目か（昇順。経路外は空）。 */
  steps: number[];
}

export interface PathTechnique {
  /** 上位経路上の要素で検出されたか。false は経路外での検出。 */
  onPath: boolean;
  /** 何歩目か（複数経路に載るなら全歩数を昇順）。 */
  steps: number[];
  severity: Severity;
  hits: TechniqueHit[];
}

/**
 * 上位 3 経路が使う ATT&CK テクニックを集める純粋関数。
 * graph / analysis は画面が表示中のものをそのまま受け取る（再計算しない）。
 * 戻りは ID そのまま（サブテクニックは親に畳まない。親の判定は UI 側）。マトリクスに無い ID は含めない。
 * attackerId は経路の先頭ノード（0 歩目）として除外するために使う。
 */
export function collectPathTechniques(
  threats: readonly ThreatView[],
  graph: AttackGraphResult,
  analysis: AnalyzeGraphResult,
  attackerId: string,
): Map<string, PathTechnique> {
  // 要素キー → 歩数の集合
  const stepsByElement = new Map<string, Set<number>>();
  const addStep = (key: string, step: number) => {
    const set = stepsByElement.get(key) ?? new Set<number>();
    set.add(step);
    stepsByElement.set(key, set);
  };
  for (const r of analysis.routes.slice(0, TOP_ROUTES)) {
    r.route.nodeIds.forEach((id, i) => {
      if (i >= 1 && id !== attackerId) addStep(nodeElementKey(id), i);
    });
    r.route.hopKeys.forEach((hk, i) => {
      for (const eid of graph.hops.get(hk)?.edgeIds ?? []) addStep(edgeElementKey(eid), i + 1);
    });
  }

  const out = new Map<string, PathTechnique>();
  for (const threat of threats) {
    if (isSuppressed(threat)) continue;
    const refs = threat.references ?? [];
    if (refs.length === 0) continue;
    const ids = extractAttackTechniqueIds(refs).filter(
      (id) => ATTACK_MATRIX.techniques.has(id) || ATTACK_MATRIX.subToParent.has(id),
    );
    if (ids.length === 0) continue;

    const key = threatElementKey(threat);
    const steps = key ? [...(stepsByElement.get(key) ?? [])].sort((a, b) => a - b) : [];
    const onPath = steps.length > 0;
    const sev = effectiveSeverity(threat);
    const hit: TechniqueHit = {
      threatId: threat.id,
      threatName: threat.name ?? threat.category,
      elementKey: key,
      steps,
    };

    for (const id of ids) {
      const cur = out.get(id) ?? { onPath: false, steps: [], severity: sev, hits: [] };
      if (SEV_RANK[sev] > SEV_RANK[cur.severity]) cur.severity = sev;
      if (onPath) {
        cur.onPath = true;
        cur.steps = [...new Set([...cur.steps, ...steps])].sort((a, b) => a - b);
      }
      cur.hits.push(hit);
      out.set(id, cur);
    }
  }
  return out;
}
