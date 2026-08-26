import type { ControlStatusValue, DreadValue, Severity, ThreatView } from '../../core/model/types';
import type { LogicalHop } from './buildAttackGraph';

/** その要素上の脅威の対策被覆度。`full` は残存経路モードで遮断扱い。 */
export type HopCoverage = 'none' | 'partial' | 'full';

/**
 * 難易度の根拠。
 * - `dread`: DREAD Exploitability 入力済み（権威ある数値）
 * - `severity-soft`: 脅威はあるが DREAD 未評価。severity から暫定導出（権威は弱い）
 * - `neutral`: 脅威なし / 既定の中立値
 */
export type DifficultyBasis = 'dread' | 'severity-soft' | 'neutral';

export function nodeElementKey(nodeId: string): string {
  return `node:${nodeId}`;
}

export function edgeElementKey(edgeId: string): string {
  return `edge:${edgeId}`;
}

/** ControlStatus のうち「対策被覆済み」とみなす status。 */
const COVERED_STATUS = new Set(['implemented', 'not-applicable']);

const COVERAGE_RANK: Record<HopCoverage, number> = { none: 0, partial: 1, full: 2 };

const SEVERITY_RANK: Record<Severity, number> = { Low: 0, Medium: 1, High: 2, Critical: 3 };

/**
 * DREAD 未評価・脅威ありの要素向け。ルール severity から暫定難易度を導出する。
 * Critical/High → 1（容易）、Medium → 2、Low → 3（困難寄り）。
 * あくまでタイブレイク／未評価時の順位付け用で、evaluated は false のまま。
 */
export const SEVERITY_SOFT_DIFFICULTY: Record<Severity, number> = {
  Critical: 1,
  High: 1,
  Medium: 2,
  Low: 3,
};

/** 検出根拠として表示する脅威 1 件分の参照。 */
export interface ThreatRef {
  threatId: string;
  /** ThreatView.name、無ければ category にフォールバック（UI と同じ規約）。 */
  name: string;
  severity: Severity;
  /** DREAD 入力済みのときのみ。 */
  exploitability?: DreadValue;
  controlStatus?: ControlStatusValue;
}

/**
 * 要素キー（`node:<id>` / `edge:<id>`）単位の重みと、その根拠（発火中の脅威一覧）。
 * `hopWeights.ts`（v1）の HopWeight を根拠つきに拡張したもの。
 */
export interface HopEvidence {
  /** 単体難易度。小さいほど攻撃が容易＝脆弱。 */
  difficulty: number;
  /** 対策被覆度。 */
  coverage: HopCoverage;
  /** その要素の脅威に DREAD 入力が 1 件でもあるか（既定値と評価済みの区別用）。 */
  evaluated: boolean;
  /** difficulty の根拠（UI で「未評価」「暫定」「DREAD」を出し分ける）。 */
  difficultyBasis: DifficultyBasis;
  /** その要素で発火している脅威（difficulty の内訳）。入力順。 */
  threats: ThreatRef[];
}

export type HopEvidenceProvider = (elementKey: string) => HopEvidence;

/** 脅威・DREAD 未評価の要素に与える中立の既定値（未評価＝安全と誤認させない）。 */
export const NEUTRAL_EVIDENCE: HopEvidence = {
  difficulty: 2,
  coverage: 'none',
  evaluated: false,
  difficultyBasis: 'neutral',
  threats: [],
};

/**
 * 脅威 refs から difficulty / evaluated / difficultyBasis を決める。
 * - max(Exploitability) > 0 → difficulty = 4 − maxE、basis=dread、evaluated=true
 * - 脅威あり・DREAD なし → severity 転用の暫定難易度、basis=severity-soft、evaluated=false
 * - 脅威なし → 中立 2、basis=neutral
 */
export function resolveDifficulty(
  maxExpl: number,
  threats: readonly ThreatRef[],
): Pick<HopEvidence, 'difficulty' | 'evaluated' | 'difficultyBasis'> {
  if (maxExpl > 0) {
    return { difficulty: 4 - maxExpl, evaluated: true, difficultyBasis: 'dread' };
  }
  if (threats.length === 0) {
    return {
      difficulty: NEUTRAL_EVIDENCE.difficulty,
      evaluated: false,
      difficultyBasis: 'neutral',
    };
  }
  let maxSev: Severity = 'Low';
  for (const t of threats) {
    if (SEVERITY_RANK[t.severity] > SEVERITY_RANK[maxSev]) maxSev = t.severity;
  }
  return {
    difficulty: SEVERITY_SOFT_DIFFICULTY[maxSev],
    evaluated: false,
    difficultyBasis: 'severity-soft',
  };
}

/**
 * 全 ThreatView を要素キー（`node:<id>` / `edge:<id>`）単位に集約し、
 * 攻撃経路分析用の HopEvidence（重み＋根拠）を構築する純粋関数。
 *
 * - evaluated: 要素内の脅威に dread.exploitability > 0（入力済み）が 1 件でもあれば true。
 * - difficulty: DREAD 優先。未評価だが脅威ありなら severity 転用（暫定）。脅威なしは中立 2。
 * - threats: その要素で発火している全脅威の ThreatRef（difficulty の内訳、入力順）。
 *
 * boundary 等 node/edge 以外を subject に持つ脅威は攻撃経路のホップにならないため無視する。
 */
export function buildHopEvidence(threats: readonly ThreatView[]): Map<string, HopEvidence> {
  const agg = new Map<string, { maxExpl: number; total: number; covered: number; refs: ThreatRef[] }>();

  for (const t of threats) {
    const kind = t.subject?.kind ?? 'node';
    if (kind !== 'node' && kind !== 'edge') continue;
    const id = t.subject?.id ?? t.nodeId;
    if (!id) continue;
    const key = kind === 'node' ? nodeElementKey(id) : edgeElementKey(id);

    const cur = agg.get(key) ?? { maxExpl: 0, total: 0, covered: 0, refs: [] };
    cur.total += 1;
    if (t.dread && t.dread.exploitability > cur.maxExpl) cur.maxExpl = t.dread.exploitability;
    if (t.controlStatus && COVERED_STATUS.has(t.controlStatus.status)) cur.covered += 1;
    cur.refs.push({
      threatId: t.id,
      name: t.name ?? t.category,
      severity: t.severity,
      exploitability: t.dread?.exploitability,
      controlStatus: t.controlStatus?.status,
    });
    agg.set(key, cur);
  }

  const evidence = new Map<string, HopEvidence>();
  for (const [key, a] of agg) {
    let coverage: HopCoverage = 'none';
    if (a.covered >= a.total) coverage = 'full';
    else if (a.covered > 0) coverage = 'partial';
    const { difficulty, evaluated, difficultyBasis } = resolveDifficulty(a.maxExpl, a.refs);
    evidence.set(key, { difficulty, coverage, evaluated, difficultyBasis, threats: a.refs });
  }
  return evidence;
}

/** 2 つの被覆度のうち、より弱い（none 寄りの）方を返す。 */
function weakerCoverage(a: HopCoverage, b: HopCoverage): HopCoverage {
  return COVERAGE_RANK[a] <= COVERAGE_RANK[b] ? a : b;
}

/**
 * 論理ホップ（並行チャネル群）を 1 つの HopEvidence に集約する。
 * - difficulty: チャネル中の最小値（攻撃者は最弱チャネルを選ぶ）
 * - coverage: チャネル中の最弱（none 寄り）。片方だけ full でも遮断とみなさない
 * - threats: 全チャネルの脅威を結合（threatId で重複排除）
 * - difficultyBasis: dread > severity-soft > neutral の優先で、寄与したチャネルの最強根拠
 */
export function aggregateLogicalHopEvidence(
  hop: LogicalHop,
  getEvidence: HopEvidenceProvider,
): HopEvidence {
  if (hop.edgeIds.length === 0) return { ...NEUTRAL_EVIDENCE };

  let minDiff = Infinity;
  let coverage: HopCoverage = 'full';
  let evaluated = false;
  let difficultyBasis: DifficultyBasis = 'neutral';
  const seen = new Set<string>();
  const threats: ThreatRef[] = [];

  const basisRank: Record<DifficultyBasis, number> = {
    neutral: 0,
    'severity-soft': 1,
    dread: 2,
  };

  for (const edgeId of hop.edgeIds) {
    const ev = getEvidence(edgeElementKey(edgeId));
    if (ev.difficulty < minDiff) minDiff = ev.difficulty;
    coverage = weakerCoverage(coverage, ev.coverage);
    if (ev.evaluated) evaluated = true;
    if (basisRank[ev.difficultyBasis] > basisRank[difficultyBasis]) {
      difficultyBasis = ev.difficultyBasis;
    }
    for (const th of ev.threats) {
      if (seen.has(th.threatId)) continue;
      seen.add(th.threatId);
      threats.push(th);
    }
  }

  if (!Number.isFinite(minDiff)) minDiff = NEUTRAL_EVIDENCE.difficulty;

  return {
    difficulty: minDiff,
    coverage,
    evaluated,
    difficultyBasis: threats.length === 0 ? 'neutral' : difficultyBasis,
    threats,
  };
}

/**
 * 経路ランキングのタイブレイク用スコア。大きいほど「脅威根拠が濃い」＝優先して脆弱扱い。
 * コスト同点のときのみ使う（コスト本体には加算しない）。
 */
export function threatEvidenceScore(threats: readonly ThreatRef[]): number {
  let score = 0;
  for (const t of threats) {
    score += 1 + SEVERITY_RANK[t.severity];
    if (t.exploitability !== undefined) score += t.exploitability;
  }
  return score;
}
