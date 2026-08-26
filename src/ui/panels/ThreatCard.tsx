import { useState } from 'react';
import {
  AlertTriangle,
  BookOpen,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Layers,
  Pencil,
  ShieldCheck,
  Target,
  Trash2,
} from 'lucide-react';
import { isSuppressed, type DetectionAssumptionFlag, type ThreatView } from '../../core/model/types';
import { useDiagramStore } from '../../core/state/diagramStore';
import { SEVERITY_BADGE_SOLID, SEVERITY_CONTAINER } from '../../core/model/severityColors';
import { componentRegistry } from '../../component-library/defaultRegistry';
import { ControlStatusEditor } from './ControlStatusEditor';
import { CONTROL_STATUS_BADGE, CONTROL_STATUS_LABEL } from './controlStatusStyle';
import { RiskTreatmentEditor } from './RiskTreatmentEditor';
import { RISK_TREATMENT_BADGE, RISK_TREATMENT_LABEL } from './riskTreatmentStyle';
import { BUNDLED_COMPLIANCE_MAP } from '../../compliance/loader/bundledComplianceMap';
import type { StandardId } from '../../compliance/schema/complianceItem';
import { summarizeAppliesTo } from './appliesToSummary';
import { useRuleLookup } from './useRuleLookup';
import { useLocale, useT } from '../../i18n';

/**
 * `complianceRefs.standard` の ID（例: `nist-ai-rmf`）を表示用の正式名称に解決する。
 * マップ未収録の ID（外部参照や旧表記）はそのまま返してフォールバック表示する。
 */
function resolveStandardLabel(standardId: string): string {
  const meta = BUNDLED_COMPLIANCE_MAP.standards.get(standardId as StandardId);
  return meta?.title ?? standardId;
}

interface ThreatCardProps {
  threat: ThreatView;
  /** ThreatListPanel のように複数ノードを横断して表示する場合のみ指定。NodePanel では省略。 */
  targetName?: string;
}

/**
 * 1 件の脅威を緩和策・コンプライアンス・出典まで含めて描画する共通カード。
 * ThreatListPanel（一覧）と NodePanel（ノード選択時）の両方から利用する。
 *
 * - origin==='manual'：編集／削除アクションを表示。
 * - origin==='detected'：リスク対応方針（回避/低減/移転/受容/誤検知）を編集できる。
 *   受容/誤検知（抑制）のときだけ淡色化し、対応方針バッジを表示する。
 */
export function ThreatCard({ threat, targetName }: ThreatCardProps) {
  const openManualThreatEditor = useDiagramStore((s) => s.openManualThreatEditor);
  const removeManualThreat = useDiagramStore((s) => s.removeManualThreat);
  const t = useT();
  const [locale] = useLocale();
  const { getRule, getSource } = useRuleLookup();
  const [isBasisOpen, setIsBasisOpen] = useState(false);

  const isManual = threat.origin === 'manual';
  // 「抑制」（淡色化）扱いは受容/誤検知のみ。回避/低減/移転は表示維持。
  const suppressed = !isManual && isSuppressed(threat);
  const detectionRule =
    threat.origin === 'detected' && threat.ruleId ? getRule(threat.ruleId) : undefined;

  const containerClass = SEVERITY_CONTAINER[threat.severity];

  const badgeClass = SEVERITY_BADGE_SOLID[threat.severity];

  return (
    <div
      className={`p-4 rounded-2xl border-l-4 ${containerClass} border-y border-r border-slate-800 transition-all ${
        suppressed ? 'opacity-60' : ''
      }`}
    >
      <div className="flex justify-between items-start mb-2">
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className={`text-[10px] font-black px-2 py-0.5 rounded-md ${badgeClass}`}>
            {threat.severity}
          </span>
          {threat.name && (
            <span className="text-[9px] font-bold px-2 py-0.5 rounded bg-slate-700/60 text-slate-300 border border-slate-600">
              {threat.category}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1.5">
          {isManual && (
            <span className="text-[9px] bg-indigo-500/20 text-indigo-300 px-2 py-0.5 rounded font-bold uppercase">
              Manual
            </span>
          )}
          {isManual && threat.manualTargetType && (
            <span
              className="text-[9px] bg-indigo-500/10 text-indigo-300/80 px-2 py-0.5 rounded font-bold"
              title="同型ノード全てに適用されるカスタムルール。編集／削除はルール全体に効きます。"
            >
              型ルール: {componentRegistry.get(threat.manualTargetType)?.label ?? threat.manualTargetType}
            </span>
          )}
          {!isManual && threat.isCustom && (
            <span className="text-[9px] bg-violet-500/20 text-violet-300 px-2 py-0.5 rounded font-bold uppercase">
              Custom
            </span>
          )}
          {!isManual && threat.isDynamic && (
            <span className="text-[9px] bg-white/10 text-slate-400 px-2 py-0.5 rounded font-bold uppercase">
              Dynamic
            </span>
          )}
          {!isManual && threat.corroboration && threat.corroboration.ruleIds.length > 1 && (
            <span
              className="text-[9px] bg-teal-500/20 text-teal-300 px-2 py-0.5 rounded font-bold inline-flex items-center gap-1"
              title="複数ソースが同一脅威を指摘しています（出典欄に全て掲載）。"
            >
              <Layers size={10} /> {threat.corroboration.ruleIds.length} ソース
            </span>
          )}
          {!isManual && threat.assumptionFlags && threat.assumptionFlags.length > 0 && (
            <span
              className="text-[9px] bg-amber-500/15 text-amber-300 px-2 py-0.5 rounded font-bold inline-flex items-center gap-1 border border-amber-500/30"
              title={threat.assumptionFlags
                .map((f: DetectionAssumptionFlag) =>
                  f === 'attackSurface'
                    ? t('threatCard.assumption.attackSurface')
                    : t('threatCard.assumption.agentAttributes'),
                )
                .join(' ')}
            >
              <AlertTriangle size={10} /> {t('threatCard.assumption.badge')}
            </span>
          )}
          {!isManual && threat.suppression && (
            <span
              className={`text-[9px] px-2 py-0.5 rounded border font-bold ${RISK_TREATMENT_BADGE[threat.suppression.status]}`}
            >
              {RISK_TREATMENT_LABEL[threat.suppression.status]}
            </span>
          )}
        </div>
      </div>
      <h4 className="font-bold text-sm mb-1 text-slate-100">{threat.name ?? threat.category}</h4>
      <p className="text-xs text-slate-400 leading-relaxed">{threat.description}</p>

      {!isManual && threat.assumptionFlags && threat.assumptionFlags.length > 0 && (
        <div className="mt-2 p-2 rounded-lg bg-amber-500/5 border border-amber-500/20 space-y-1">
          {threat.assumptionFlags.includes('attackSurface') && (
            <p className="text-xs text-amber-200/90 leading-relaxed">
              {t('threatCard.assumption.attackSurface')}
            </p>
          )}
          {threat.assumptionFlags.includes('agentAttributes') && (
            <p className="text-xs text-amber-200/90 leading-relaxed">
              {t('threatCard.assumption.agentAttributes')}
            </p>
          )}
        </div>
      )}

      {threat.mitigationTiers ? (
        <div className="mt-3 p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20 space-y-2">
          <div className="flex items-center gap-1.5 text-[10px] font-black text-emerald-400 uppercase tracking-widest">
            <ShieldCheck size={12} /> 緩和策（3 段階成熟度）
          </div>
          {(['foundation', 'enterprise', 'advanced'] as const).map((tier) => {
            const value = threat.mitigationTiers?.[tier];
            if (!value) return null;
            const tierLabel = tier === 'foundation' ? 'Foundation' : tier === 'enterprise' ? 'Enterprise' : 'Advanced';
            const tierBadge =
              tier === 'foundation'
                ? 'bg-emerald-500/15 text-emerald-300'
                : tier === 'enterprise'
                  ? 'bg-sky-500/15 text-sky-300'
                  : 'bg-violet-500/15 text-violet-300';
            return (
              <div key={tier} className="flex gap-2">
                <span
                  className={`shrink-0 h-fit text-[9px] font-black uppercase tracking-wider px-1.5 py-0.5 rounded ${tierBadge}`}
                >
                  {tierLabel}
                </span>
                <p className="text-xs text-slate-300 leading-relaxed">{value}</p>
              </div>
            );
          })}
        </div>
      ) : (
        threat.mitigation && (
          <div className="mt-3 p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
            <div className="flex items-center gap-1.5 mb-1 text-[10px] font-black text-emerald-400 uppercase tracking-widest">
              <ShieldCheck size={12} /> 緩和策
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">{threat.mitigation}</p>
          </div>
        )
      )}

      {threat.complianceRefs && threat.complianceRefs.length > 0 && (
        <div className="mt-3">
          <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1.5">
            コンプライアンス
          </div>
          <div className="flex flex-wrap gap-1.5">
            {threat.complianceRefs.map((c, i) => {
              const label = resolveStandardLabel(c.standard);
              return (
                <span
                  key={`${c.standard}-${c.ref}-${i}`}
                  className="text-[10px] font-bold bg-slate-800 border border-slate-700 text-slate-300 px-2 py-0.5 rounded"
                  title={`${label} / ${c.ref}`}
                >
                  {label} <span className="text-slate-500">·</span> {c.ref}
                </span>
              );
            })}
          </div>
        </div>
      )}

      {threat.references && threat.references.length > 0 && (
        <div className="mt-3">
          <div className="flex items-center gap-1.5 text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1.5">
            <BookOpen size={12} /> 出典
          </div>
          <ul className="space-y-1">
            {threat.references.map((r, i) => (
              <li key={`${r.title}-${i}`} className="text-[11px] text-slate-400 leading-snug">
                {r.url ? (
                  <a
                    href={r.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300 hover:underline"
                  >
                    {r.title}
                    <ExternalLink size={10} />
                  </a>
                ) : (
                  <span>{r.title}</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* ── 検出根拠（どのルールが・どの条件で発火したか） ── */}
      {detectionRule && (
        <div className="mt-3 pt-3 border-t border-white/5">
          <button
            type="button"
            onClick={() => setIsBasisOpen((v) => !v)}
            className="flex items-center gap-1.5 text-[10px] font-black text-slate-500 uppercase tracking-widest hover:text-slate-300 transition-colors"
          >
            {isBasisOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
            {t('threatCard.detectionBasis.heading')}
          </button>
          {isBasisOpen && (
            <div className="mt-2 space-y-2">
              <p className="text-xs text-slate-400 leading-relaxed">
                {summarizeAppliesTo(detectionRule.appliesTo, locale)}
              </p>
              <p className="text-xs text-slate-500">
                {t('threatCard.detectionBasis.ruleLabel')}: {getSource(threat.ruleId!) ?? threat.ruleId} /{' '}
                {threat.ruleId}
              </p>
              {threat.corroboration && threat.corroboration.ruleIds.length > 1 && (
                <div>
                  <div className="text-xs text-slate-500 mb-1">
                    {t('threatCard.detectionBasis.corroboratedRules')}
                  </div>
                  <ul className="space-y-0.5">
                    {threat.corroboration.ruleIds.map((rid) => (
                      <li key={rid} className="text-xs text-slate-500">
                        {getSource(rid) ?? rid} / {rid}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── 対策実装状況（リスク対応方針=suppression とは別レイヤー） ── */}
      <div className="mt-3 pt-3 border-t border-white/5">
        <div className="flex items-center gap-2 mb-2">
          <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">
            対策実装状況
          </span>
          {threat.controlStatus && (
            <span
              className={`text-[9px] px-2 py-0.5 rounded border ${CONTROL_STATUS_BADGE[threat.controlStatus.status]}`}
            >
              {CONTROL_STATUS_LABEL[threat.controlStatus.status]}
            </span>
          )}
        </div>
        <ControlStatusEditor key={threat.id} threat={threat} />
      </div>

      {/* ── リスク対応方針（対策実装状況=controlStatus とは別レイヤー） ── */}
      {!isManual && (
        <div className="mt-3 pt-3 border-t border-white/5">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">
              リスク対応方針
            </span>
            {threat.suppression && (
              <span
                className={`text-[9px] px-2 py-0.5 rounded border ${RISK_TREATMENT_BADGE[threat.suppression.status]}`}
              >
                {RISK_TREATMENT_LABEL[threat.suppression.status]}
              </span>
            )}
          </div>
          <RiskTreatmentEditor key={threat.id} threat={threat} />
        </div>
      )}

      {/* ── アクション ── */}
      {isManual && (
        <div className="mt-3 pt-3 border-t border-white/5 flex items-center justify-end gap-2">
          <button
            onClick={() => openManualThreatEditor(threat.manualId)}
            className="flex items-center gap-1 text-[10px] font-bold uppercase text-slate-400 hover:text-slate-100 transition-colors"
          >
            <Pencil size={12} /> 編集
          </button>
          <button
            onClick={() => removeManualThreat(threat.manualId!)}
            className="flex items-center gap-1 text-[10px] font-bold uppercase text-rose-400 hover:text-rose-300 transition-colors"
          >
            <Trash2 size={12} /> 削除
          </button>
        </div>
      )}

      {targetName && (
        <div className="mt-3 pt-3 border-t border-white/5 flex items-center justify-between text-[10px] font-black text-slate-500 uppercase">
          <span className="flex items-center gap-1">
            <Target size={12} /> {targetName}
          </span>
          <ChevronRight size={14} />
        </div>
      )}
    </div>
  );
}
