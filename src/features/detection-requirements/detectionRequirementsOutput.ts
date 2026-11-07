import { translate, type TranslationKey } from '../../i18n';
import type { DetectionNode, DetectionRequirements } from './buildDetectionRequirements';

/** 検知要件（DetectionRequirements）を Markdown / JSON に整形する。 */

const oneLine = (s: string) => s.replace(/\s+/g, ' ').trim();

type T = (key: TranslationKey, params?: Record<string, string | number>) => string;

function logLine(n: DetectionNode, t: T): string {
  if (!n.log) return t('detection.log.notModelable');
  if (n.log.state === 'forwarded') return t('detection.log.forwarded');
  if (n.log.state === 'localOnly') return t('detection.log.localOnly');
  return t(n.log.assumed ? 'detection.log.noneAssumed' : 'detection.log.none');
}

export function detectionRequirementsToMarkdown(d: DetectionRequirements): string {
  const t: T = (key, params) => translate(key, d.locale, params);
  const out: string[] = [];

  out.push(`# ${t('detection.title', { system: d.system, layer: d.layer })}`, '');
  out.push(`> ${t('detection.disclaimer')}`, '');
  out.push(`- ${t('detection.system', { system: d.system })}`);
  out.push(`- ${t('detection.generated', { date: d.generatedAt, product: d.product })}`);
  out.push(`- ${d.pathBased ? t('detection.scope.path') : t('detection.scope.all')}`, '');

  if (d.routes.length > 0) {
    out.push(`## ${t('detection.h.routes')}`, '');
    if (d.totalRoutes > d.routes.length) {
      out.push(t('detection.routes.truncated', { shown: d.routes.length, total: d.totalRoutes }), '');
    }
    d.routes.forEach((r, i) => {
      out.push(`### ${t('detection.route', { n: i + 1, attacker: r.attacker, objective: r.objective })}`, '');
      out.push(`- ${t('detection.route.nodes', { nodes: r.nodes.join(' → ') })}`);
      if (r.blind) out.push(`- ${t('detection.route.blind')}`);
      if (r.gaps.length === 0) out.push(`- ${t('detection.route.noGap')}`);
      for (const g of r.gaps) out.push(`- ${t('detection.route.gap', { nodes: g.join(' → ') })}`);
      out.push('');
    });
  }

  out.push(`## ${t('detection.h.nodes')}`, '');
  if (d.nodes.length === 0) out.push(t('detection.nodes.none'), '');
  for (const n of d.nodes) {
    out.push(`### ${`${n.id} ${n.label}`.trim()}（${n.type}）`, '');
    if (n.routeHits !== null) out.push(`- ${t('detection.routeHits', { hits: n.routeHits })}`);
    out.push(`- ${t('detection.logState', { state: logLine(n, t) })}`, '');
    if (n.requirements.length === 0) out.push(`_${t('detection.noRequirement')}_`, '');
    for (const r of n.requirements) {
      const attack = r.attack.length > 0 ? ` [${r.attack.join(', ')}]` : '';
      out.push(`**${t('detection.requirement', { title: r.title, threats: [...new Set(r.threatNames)].join(', ') })}**${attack}`, '');
      out.push(t('detection.watch'));
      for (const w of r.watch) out.push(`- ${oneLine(w)}`);
      out.push('', t('detection.logs'));
      for (const l of r.logs) out.push(`- ${oneLine(l)}`);
      out.push('');
    }
  }
  return `${out.join('\n').trimEnd()}\n`;
}

/** JSON は DetectionRequirements をそのまま出す（キーは英語）。 */
export function detectionRequirementsToJson(d: DetectionRequirements): string {
  return JSON.stringify(d, null, 2);
}
