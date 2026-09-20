import { ExternalLink, ShieldCheck } from 'lucide-react';
import { useT, type TranslationKey } from '../../i18n';

/**
 * 「Zero Trust for AI Agents」フレームワークの一枚絵ビュー。
 *
 * Compliance Map モーダル内の固定エントリとして表示される静的な参照ページ。
 * 内容は Anthropic「Zero Trust for AI Agents」eBook (2026) の要約で、
 * 脅威エンジンのルールではなくプレゼンテーション専用データとして本ファイルに保持する。
 * 規格本文の転載は行わず、独自要約と出典リンクのみを示す。
 * 表示文言は日本語。技術略語・固有名詞（RBAC/ABAC/MCP/constitutional classifiers 等）は原語のまま。
 */

const SOURCE_URL = 'https://www.anthropic.com';

type Principle = { titleKey: TranslationKey; bodyKey: TranslationKey };

const PRINCIPLES: Principle[] = [
  {
    titleKey: 'zeroTrust.principles.neverTrust.title',
    bodyKey: 'zeroTrust.principles.neverTrust.body',
  },
  {
    titleKey: 'zeroTrust.principles.assumeBreach.title',
    bodyKey: 'zeroTrust.principles.assumeBreach.body',
  },
  {
    titleKey: 'zeroTrust.principles.leastAgency.title',
    bodyKey: 'zeroTrust.principles.leastAgency.body',
  },
];

type WhyNow = { statKey: TranslationKey; bodyKey: TranslationKey };

const WHY_NOW: WhyNow[] = [
  {
    statKey: 'zeroTrust.whyNow.speedOfExploit.stat',
    bodyKey: 'zeroTrust.whyNow.speedOfExploit.body',
  },
  {
    statKey: 'zeroTrust.whyNow.backdoorDocs.stat',
    bodyKey: 'zeroTrust.whyNow.backdoorDocs.body',
  },
  {
    statKey: 'zeroTrust.whyNow.spotlighting.stat',
    bodyKey: 'zeroTrust.whyNow.spotlighting.body',
  },
  {
    statKey: 'zeroTrust.whyNow.jailbreakBlockRate.stat',
    bodyKey: 'zeroTrust.whyNow.jailbreakBlockRate.body',
  },
];

type Tier = 'foundation' | 'enterprise' | 'advanced';

const TIER_META: Record<
  Tier,
  { labelKey: TranslationKey; taglineKey: TranslationKey; accent: string }
> = {
  foundation: {
    labelKey: 'zeroTrust.matrix.tier.foundation.label',
    taglineKey: 'zeroTrust.matrix.tier.foundation.tagline',
    accent: 'text-sky-400 border-sky-500/60',
  },
  enterprise: {
    labelKey: 'zeroTrust.matrix.tier.enterprise.label',
    taglineKey: 'zeroTrust.matrix.tier.enterprise.tagline',
    accent: 'text-emerald-400 border-emerald-500/60',
  },
  advanced: {
    labelKey: 'zeroTrust.matrix.tier.advanced.label',
    taglineKey: 'zeroTrust.matrix.tier.advanced.tagline',
    accent: 'text-amber-400 border-amber-500/60',
  },
};

type Domain = {
  nameKey: TranslationKey;
  foundationKey: TranslationKey;
  enterpriseKey: TranslationKey;
  advancedKey: TranslationKey;
};

const DOMAINS: Domain[] = [
  {
    nameKey: 'zeroTrust.matrix.domain.identityAuth.name',
    foundationKey: 'zeroTrust.matrix.domain.identityAuth.foundation',
    enterpriseKey: 'zeroTrust.matrix.domain.identityAuth.enterprise',
    advancedKey: 'zeroTrust.matrix.domain.identityAuth.advanced',
  },
  {
    nameKey: 'zeroTrust.matrix.domain.accessControl.name',
    foundationKey: 'zeroTrust.matrix.domain.accessControl.foundation',
    enterpriseKey: 'zeroTrust.matrix.domain.accessControl.enterprise',
    advancedKey: 'zeroTrust.matrix.domain.accessControl.advanced',
  },
  {
    nameKey: 'zeroTrust.matrix.domain.observability.name',
    foundationKey: 'zeroTrust.matrix.domain.observability.foundation',
    enterpriseKey: 'zeroTrust.matrix.domain.observability.enterprise',
    advancedKey: 'zeroTrust.matrix.domain.observability.advanced',
  },
  {
    nameKey: 'zeroTrust.matrix.domain.behaviorMonitoring.name',
    foundationKey: 'zeroTrust.matrix.domain.behaviorMonitoring.foundation',
    enterpriseKey: 'zeroTrust.matrix.domain.behaviorMonitoring.enterprise',
    advancedKey: 'zeroTrust.matrix.domain.behaviorMonitoring.advanced',
  },
  {
    nameKey: 'zeroTrust.matrix.domain.ioControl.name',
    foundationKey: 'zeroTrust.matrix.domain.ioControl.foundation',
    enterpriseKey: 'zeroTrust.matrix.domain.ioControl.enterprise',
    advancedKey: 'zeroTrust.matrix.domain.ioControl.advanced',
  },
  {
    nameKey: 'zeroTrust.matrix.domain.integrityRecovery.name',
    foundationKey: 'zeroTrust.matrix.domain.integrityRecovery.foundation',
    enterpriseKey: 'zeroTrust.matrix.domain.integrityRecovery.enterprise',
    advancedKey: 'zeroTrust.matrix.domain.integrityRecovery.advanced',
  },
  {
    nameKey: 'zeroTrust.matrix.domain.aiGovernance.name',
    foundationKey: 'zeroTrust.matrix.domain.aiGovernance.foundation',
    enterpriseKey: 'zeroTrust.matrix.domain.aiGovernance.enterprise',
    advancedKey: 'zeroTrust.matrix.domain.aiGovernance.advanced',
  },
];

type Threat = { titleKey: TranslationKey; bodyKey: TranslationKey };

const THREATS: Threat[] = [
  {
    titleKey: 'zeroTrust.threats.promptInjection.title',
    bodyKey: 'zeroTrust.threats.promptInjection.body',
  },
  {
    titleKey: 'zeroTrust.threats.toolAbuse.title',
    bodyKey: 'zeroTrust.threats.toolAbuse.body',
  },
  {
    titleKey: 'zeroTrust.threats.identityAbuse.title',
    bodyKey: 'zeroTrust.threats.identityAbuse.body',
  },
  {
    titleKey: 'zeroTrust.threats.supplyChain.title',
    bodyKey: 'zeroTrust.threats.supplyChain.body',
  },
  {
    titleKey: 'zeroTrust.threats.memoryPoisoning.title',
    bodyKey: 'zeroTrust.threats.memoryPoisoning.body',
  },
];

type Phase = { titleKey: TranslationKey; bodyKey: TranslationKey };

const PHASES: Phase[] = [
  {
    titleKey: 'zeroTrust.workflow.phase.identifyRequirements.title',
    bodyKey: 'zeroTrust.workflow.phase.identifyRequirements.body',
  },
  {
    titleKey: 'zeroTrust.workflow.phase.protectSupplyChain.title',
    bodyKey: 'zeroTrust.workflow.phase.protectSupplyChain.body',
  },
  {
    titleKey: 'zeroTrust.workflow.phase.defineAgentBoundaries.title',
    bodyKey: 'zeroTrust.workflow.phase.defineAgentBoundaries.body',
  },
  {
    titleKey: 'zeroTrust.workflow.phase.defendPromptInjection.title',
    bodyKey: 'zeroTrust.workflow.phase.defendPromptInjection.body',
  },
  {
    titleKey: 'zeroTrust.workflow.phase.secureToolAccess.title',
    bodyKey: 'zeroTrust.workflow.phase.secureToolAccess.body',
  },
  {
    titleKey: 'zeroTrust.workflow.phase.protectCredentials.title',
    bodyKey: 'zeroTrust.workflow.phase.protectCredentials.body',
  },
  {
    titleKey: 'zeroTrust.workflow.phase.protectMemory.title',
    bodyKey: 'zeroTrust.workflow.phase.protectMemory.body',
  },
  {
    titleKey: 'zeroTrust.workflow.phase.measureMetrics.title',
    bodyKey: 'zeroTrust.workflow.phase.measureMetrics.body',
  },
];

function SectionTitle({ children, accent }: { children: string; accent: string }) {
  return (
    <h4 className={`text-xs font-black uppercase tracking-widest ${accent} mb-3`}>
      {children}
    </h4>
  );
}

export function ZeroTrustForAiAgents() {
  const t = useT();
  return (
    <div className="flex-1 overflow-y-auto px-6 py-5">
      {/* ヘッダー */}
      <div className="flex items-start justify-between gap-4 flex-wrap border-b border-slate-800 pb-4">
        <div className="flex items-start gap-3">
          <ShieldCheck size={24} className="text-emerald-400 shrink-0 mt-0.5" />
          <div>
            <h3 className="text-xl font-black tracking-tight text-slate-100">
              ZERO TRUST FOR AI AGENTS
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              {t('zeroTrust.header.subtitle')}
            </p>
          </div>
        </div>
        <div className="text-right">
          <p className="text-sm font-bold italic text-emerald-400">
            {t('zeroTrust.header.quote')}
          </p>
          <a
            href={SOURCE_URL}
            target="_blank"
            rel="noreferrer noopener"
            className="inline-flex items-center gap-1 text-[10px] text-slate-500 hover:text-emerald-400 transition-colors mt-1"
          >
            {t('zeroTrust.header.source')} <ExternalLink size={10} />
          </a>
        </div>
      </div>

      {/* 原則 + 今こそ必要な理由 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-5">
        <div>
          <SectionTitle accent="text-emerald-400">
            {t('zeroTrust.principles.sectionTitle')}
          </SectionTitle>
          <div className="flex flex-col gap-2">
            {PRINCIPLES.map((p) => (
              <div
                key={p.titleKey}
                className="p-3 rounded-lg bg-slate-800/40 border-l-2 border-emerald-500/60"
              >
                <div className="text-xs font-bold text-slate-100">{t(p.titleKey)}</div>
                <p className="text-[11px] text-slate-400 leading-relaxed mt-1">
                  {t(p.bodyKey)}
                </p>
              </div>
            ))}
            <div className="p-3 rounded-lg bg-amber-500/5 border border-amber-500/40">
              <div className="text-xs font-bold text-amber-400">
                {t('zeroTrust.principles.designTest.title')}
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed mt-1">
                {t('zeroTrust.principles.designTest.body')}
              </p>
            </div>
          </div>
        </div>

        <div>
          <SectionTitle accent="text-emerald-400">
            {t('zeroTrust.whyNow.sectionTitle')}
          </SectionTitle>
          <div className="flex flex-col gap-2">
            {WHY_NOW.map((w) => (
              <div
                key={w.statKey}
                className="flex items-baseline gap-3 p-3 rounded-lg bg-slate-800/40 border border-slate-800"
              >
                <span className="text-sm font-black text-sky-400 shrink-0 w-28 tabular-nums">
                  {t(w.statKey)}
                </span>
                <p className="text-[11px] text-slate-400 leading-relaxed">{t(w.bodyKey)}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 能力マトリクス */}
      <div className="mt-8">
        <SectionTitle accent="text-emerald-400">
          {t('zeroTrust.matrix.sectionTitle')}
        </SectionTitle>
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full border-collapse text-left">
            <thead>
              <tr className="bg-slate-800/60">
                <th className="p-3 text-[10px] font-bold uppercase tracking-wider text-slate-500 w-44 align-top">
                  {t('zeroTrust.matrix.domainHeader')}
                </th>
                {(['foundation', 'enterprise', 'advanced'] as Tier[]).map((tier) => (
                  <th
                    key={tier}
                    className={`p-3 align-top border-l border-slate-800 border-t-2 ${TIER_META[tier].accent}`}
                  >
                    <div className="text-xs font-black">{t(TIER_META[tier].labelKey)}</div>
                    <div className="text-[10px] font-normal text-slate-500 italic mt-0.5">
                      {t(TIER_META[tier].taglineKey)}
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {DOMAINS.map((d) => (
                <tr key={d.nameKey} className="border-t border-slate-800">
                  <td className="p-3 text-xs font-bold text-slate-200 align-top">
                    {t(d.nameKey)}
                  </td>
                  <td className="p-3 text-[11px] text-slate-400 leading-relaxed align-top border-l border-slate-800">
                    {t(d.foundationKey)}
                  </td>
                  <td className="p-3 text-[11px] text-slate-400 leading-relaxed align-top border-l border-slate-800">
                    {t(d.enterpriseKey)}
                  </td>
                  <td className="p-3 text-[11px] text-slate-400 leading-relaxed align-top border-l border-slate-800">
                    {t(d.advancedKey)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-[11px] text-slate-500 italic mt-2">
          {t('zeroTrust.matrix.footnote.lead')}{' '}
          <span className="font-bold text-slate-400">
            {t('zeroTrust.matrix.footnote.emphasis')}
          </span>
        </p>
      </div>

      {/* 脅威 */}
      <div className="mt-8">
        <SectionTitle accent="text-rose-400">{t('zeroTrust.threats.sectionTitle')}</SectionTitle>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {THREATS.map((thr, i) => (
            <div
              key={thr.titleKey}
              className="p-3 rounded-lg bg-slate-800/40 border-l-2 border-rose-500/60"
            >
              <div className="text-xs font-bold text-slate-100">
                {i + 1}. {t(thr.titleKey)}
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed mt-1">{t(thr.bodyKey)}</p>
            </div>
          ))}
          <div className="p-3 rounded-lg border border-emerald-500/40 bg-emerald-500/5">
            <p className="text-[11px] text-emerald-300/90 leading-relaxed">
              <span className="font-bold">{t('zeroTrust.threats.baselineRising.label')}</span>
              {t('zeroTrust.threats.baselineRising.body')}
            </p>
          </div>
        </div>
      </div>

      {/* 実装ワークフロー */}
      <div className="mt-8">
        <SectionTitle accent="text-emerald-400">
          {t('zeroTrust.workflow.sectionTitle')}
        </SectionTitle>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          {PHASES.map((p, i) => (
            <div
              key={p.titleKey}
              className="p-3 rounded-lg bg-slate-800/40 border-t-2 border-emerald-500/60"
            >
              <div className="text-xs font-bold text-slate-100">
                {i + 1}. {t(p.titleKey)}
              </div>
              <p className="text-[10px] text-slate-500 leading-relaxed mt-1">{t(p.bodyKey)}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
