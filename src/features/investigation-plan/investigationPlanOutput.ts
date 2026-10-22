import { translate, type TranslationKey } from '../../i18n';
import type { InvestigationNode, InvestigationPlan } from './buildInvestigationPlan';

/** 調査計画（InvestigationPlan）を Markdown / JSON に整形する。 */

const oneLine = (s: string) => s.replace(/\s+/g, ' ').trim();

type T = (key: TranslationKey, params?: Record<string, string | number>) => string;

export function investigationPlanToMarkdown(plan: InvestigationPlan): string {
  const t: T = (key, params) => translate(key, plan.locale, params);
  const out: string[] = [];

  out.push(`# ${t('investigation.title', { system: plan.system, layer: plan.layer })}`, '');
  out.push(`> ${t('investigation.disclaimer')}`, '');
  out.push(`- ${t('investigation.system', { system: plan.system })}`);
  out.push(`- ${t('investigation.generated', { date: plan.generatedAt, product: plan.product })}`);
  out.push(`- ${plan.pathBased ? t('investigation.scope.path') : t('investigation.scope.all')}`);
  out.push(`- ${t('investigation.howTo')}`, '');

  out.push(`## ${t('investigation.h.nodes')}`, '');
  if (plan.nodes.length === 0) out.push(t('investigation.nodes.none'), '');
  for (const n of plan.nodes) {
    out.push(`### ${`${n.id} ${n.label}`.trim()}（${n.type}）`, '');
    if (n.routeHits !== null) out.push(`- ${t('investigation.routeHits', { hits: n.routeHits })}`, '');
    if (n.viewpoints.length === 0) out.push(`_${t('investigation.noViewpoint')}_`, '');
    for (const v of n.viewpoints) {
      out.push(`**${t('investigation.viewpoint', { title: v.title, threats: [...new Set(v.threatNames)].join(', ') })}**`, '');
      for (const c of v.checks) out.push(`- [ ] ${oneLine(c)}`);
      for (const a of v.accepted) {
        out.push(
          `- ${t(a.note ? 'investigation.accepted.note' : 'investigation.accepted', { threat: a.threat, note: oneLine(a.note) })}`,
        );
      }
      out.push('', t('investigation.logs'));
      for (const l of v.logs) out.push(`- ${oneLine(l)}`);
      if (v.toolSteps && plan.tool) {
        out.push('', t('investigation.toolHint', { tool: plan.tool }));
        for (const s of v.toolSteps) {
          const params = Object.entries(s.parameters ?? {}).map(([k, val]) => `${k}=${val}`);
          out.push(`- \`${s.artifact}\`${params.length ? ` — ${params.map((p) => `\`${p}\``).join(', ')}` : ''}`);
        }
      }
      out.push('');
    }
    out.push(...limitationLines(n, t));
  }
  return `${out.join('\n').trimEnd()}\n`;
}

function limitationLines(n: InvestigationNode, t: T): string[] {
  const lines = [`**${t('investigation.limitations')}**`, ''];
  if (n.limitations.length === 0) lines.push(`- ${t('investigation.limit.none')}`);
  for (const l of n.limitations) lines.push(`- ${t(`investigation.limit.${l.code}` as TranslationKey)}`);
  lines.push('');
  return lines;
}

/** JSON は InvestigationPlan をそのまま出す（キーは英語）。 */
export function investigationPlanToJson(plan: InvestigationPlan): string {
  return JSON.stringify(plan, null, 2);
}
