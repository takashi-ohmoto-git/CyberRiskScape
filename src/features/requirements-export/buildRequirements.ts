import type { DiagramEdge, DiagramNode, LayerKey, ProjectMeta, Severity, ThreatView } from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import { BRANDING } from '../../core/branding';
import { getLocale, type Locale } from '../../i18n';
import { getStageMap, STAGES, type Stage } from './stageMap';

/**
 * 脅威モデルから、設計段階で明確にしておくべきセキュリティ要件の一覧（たたき台）を作る純粋関数。
 *
 * - 1 行 = （canonicalId または ruleId でまとめた脅威グループ × 緩和策の段階）。ノードをまたいで集約する。
 * - 要件文は脅威ルールの緩和策（[Foundation]/[Enterprise]/[Advanced] の各段階）。ローダーが
 *   `mitigationTiers` に展開済みなのでそれを読む。段階の無い緩和策は Foundation 扱い。
 * - 工程と委託先への要件は `data/requirement-maps/process-stages.yaml`（コードは持たない）。
 * - 誤検知は除く。リスク受容は残し、`accepted` で「実施しないと決めた」ことを示す。
 * - 要件の採否は人間が決める。ここでは候補を出すだけ。
 */

export interface RequirementsInput {
  threats: ThreatView[];
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  projectMeta: ProjectMeta;
  layer: LayerKey;
}

export type RequirementTier = 'Foundation' | 'Enterprise' | 'Advanced';
const TIERS: readonly RequirementTier[] = ['Foundation', 'Enterprise', 'Advanced'];
const TIER_KEY = { Foundation: 'foundation', Enterprise: 'enterprise', Advanced: 'advanced' } as const;

export interface RequirementRow {
  /** REQ-001 …（重大度の高い順、同じなら canonicalId 順）。 */
  id: string;
  tier: RequirementTier;
  text: string;
  /** 対象ノード（ElementalID と表示名）。 */
  targets: { id: string; name: string }[];
  /** 根拠の脅威名（重複なし）。 */
  threats: string[];
  maxSeverity: Severity;
  stages: Stage[];
  /** NIST CSF 2.0 の参照（例: GV.SC-07）。 */
  csfRefs: string[];
  /** 委託先へ求める要件（`contractorRequirements`）のトリガーに当たる脅威が根拠か。 */
  contractor: boolean;
  /** 根拠の脅威がすべてリスク受容済み＝「実施しない」と判断されている。 */
  accepted: boolean;
  acceptedNotes: string[];
}

export interface ContractorRequirementRow {
  id: string;
  text: string;
  /** この要件を求める根拠になった脅威名。 */
  threats: string[];
}

export interface RequirementsList {
  locale: Locale;
  product: string;
  system: string;
  layer: LayerKey;
  /** 生成日（YYYY-MM-DD）。 */
  generatedAt: string;
  stageLabels: Record<Stage, string>;
  requirements: RequirementRow[];
  contractorRequirements: ContractorRequirementRow[];
}

const SEVERITY_RANK: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 };

const CSF_STANDARD = 'nist-csf-2.0';

interface Group {
  key: string;
  canonicalId?: string;
  threats: ThreatView[];
}

export function buildRequirements(
  input: RequirementsInput,
  now: Date,
  locale: Locale = getLocale(),
): RequirementsList {
  const map = getStageMap(locale);
  const nodeById = new Map(input.nodes.map((n) => [n.id, n]));

  // 誤検知は当たらないので除く。ノード以外（エッジ等）への脅威は対象ノードを示せないので除く。
  const live = input.threats.filter(
    (t) => t.suppression?.status !== 'false-positive' && !(t.subject && t.subject.kind !== 'node'),
  );

  // 委託先への要件：トリガーの canonicalId の脅威が 1 件でもあるものだけ。
  const contractorTriggerIds = new Set<string>();
  const contractorRequirements: ContractorRequirementRow[] = [];
  for (const def of map.contractorRequirements) {
    const hit = live.filter((t) => t.canonicalId && def.triggers.includes(t.canonicalId));
    if (hit.length === 0) continue;
    for (const c of def.triggers) contractorTriggerIds.add(c);
    contractorRequirements.push({
      id: def.id,
      text: def.text,
      threats: [...new Set(hit.map((t) => t.name ?? t.category))],
    });
  }

  const groups = new Map<string, Group>();
  for (const t of live) {
    if (!t.mitigation && !t.mitigationTiers) continue;
    const key = t.canonicalId ?? t.ruleId ?? t.id;
    const g = groups.get(key) ?? { key, canonicalId: t.canonicalId, threats: [] };
    g.threats.push(t);
    groups.set(key, g);
  }

  const rows: Omit<RequirementRow, 'id'>[] = [];
  const sortKey: string[] = [];
  for (const g of groups.values()) {
    // 重大度の高い脅威を先頭にして、その緩和策文を要件文に使う。
    const threats = [...g.threats].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
    const stages = (g.canonicalId ? map.stages[g.canonicalId] : undefined) ?? map.default;
    const orderedStages = STAGES.filter((s) => stages.includes(s));
    const csfRefs = [
      ...new Set(
        threats.flatMap((t) => (t.complianceRefs ?? []).filter((r) => r.standard === CSF_STANDARD).map((r) => r.ref)),
      ),
    ].sort();
    const targetIds = [...new Set(threats.map((t) => t.subject?.id ?? t.nodeId))];
    const targets = targetIds
      .map((id) => nodeById.get(id))
      .filter((n): n is DiagramNode => !!n)
      .sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0))
      .map((n) => ({
        id: n.seq != null ? formatElementalId('node', n.seq) : n.id,
        name: getNodeDisplayName(n),
      }));
    if (targets.length === 0) continue;
    const accepted = threats.every((t) => t.suppression?.status === 'accepted');
    const acceptedNotes = [
      ...new Set(threats.filter((t) => t.suppression?.status === 'accepted').map((t) => t.suppression?.note?.trim() ?? '')),
    ].filter((s) => s !== '');

    for (const tier of TIERS) {
      const source = threats.find((t) => (t.mitigationTiers?.[TIER_KEY[tier]] ?? '') !== '');
      let text = source?.mitigationTiers?.[TIER_KEY[tier]];
      // 段階の無い緩和策は Foundation として扱う。
      if (!text && tier === 'Foundation' && !threats.some((t) => t.mitigationTiers)) {
        text = threats.find((t) => t.mitigation)?.mitigation;
      }
      if (!text) continue;
      rows.push({
        tier,
        text: text.replace(/\s+/g, ' ').trim(),
        targets,
        threats: [...new Set(threats.map((t) => t.name ?? t.category))],
        maxSeverity: threats[0].severity,
        stages: orderedStages,
        csfRefs,
        contractor: !!g.canonicalId && contractorTriggerIds.has(g.canonicalId),
        accepted,
        acceptedNotes,
      });
      sortKey.push(g.key);
    }
  }

  // 重大度の高い順 → グループキー → 段階の順（rows は段階順に積んでいるので安定ソートで保たれる）。
  const order = rows.map((_, i) => i);
  order.sort(
    (a, b) =>
      SEVERITY_RANK[rows[b].maxSeverity] - SEVERITY_RANK[rows[a].maxSeverity] ||
      sortKey[a].localeCompare(sortKey[b]) ||
      TIERS.indexOf(rows[a].tier) - TIERS.indexOf(rows[b].tier),
  );
  const requirements = order.map((i, n) => ({ id: `REQ-${String(n + 1).padStart(3, '0')}`, ...rows[i] }));

  return {
    locale,
    product: BRANDING.name,
    system: input.projectMeta.systemName.trim() || input.projectMeta.name.trim() || BRANDING.name,
    layer: input.layer,
    generatedAt: `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`,
    stageLabels: map.stageLabels,
    requirements,
    contractorRequirements,
  };
}
