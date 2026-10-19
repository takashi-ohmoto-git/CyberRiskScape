import { translate, type TranslationKey } from '../../i18n';
import type { PlanElement, TestPlan } from './buildTestPlan';

/** 脅威モデルから作ったテスト計画（TestPlan）を Markdown / JSON に整形する。 */

const el = (e: PlanElement) => `${e.id} ${e.label}`.trim();
/** 箇条書き 1 行に収めるため、改行を空白にする。 */
const oneLine = (s: string) => s.replace(/\s+/g, ' ').trim();

export function testPlanToMarkdown(plan: TestPlan): string {
  const t = (key: TranslationKey, params?: Record<string, string | number>) => translate(key, plan.locale, params);
  const out: string[] = [];

  out.push(`# ${t('testPlan.title', { system: plan.system, layer: plan.layer })}`, '');

  // 1. 概要と前提
  out.push(`## ${t('testPlan.h.overview')}`, '');
  out.push(`- ${t('testPlan.overview.system', { system: plan.system })}`);
  out.push(`- ${t('testPlan.overview.layer', { layer: plan.layer, framework: plan.framework })}`);
  out.push(`- ${t('testPlan.overview.generated', { date: plan.generatedAt, product: plan.product })}`, '');
  out.push(`> ${t('testPlan.overview.authorizedOnly')}`, '');
  for (const k of [1, 2, 3, 4] as const) out.push(`- ${t(`testPlan.overview.howTo${k}`)}`);
  out.push('', t('testPlan.overview.note'), '');

  // 2. 範囲（入口）
  out.push(`## ${t('testPlan.h.scope')}`, '');
  if (plan.entryPoints.length === 0) {
    out.push(t('testPlan.scope.none'), '');
  } else {
    out.push(t('testPlan.scope.rule'), '');
    for (const ep of plan.entryPoints) {
      out.push(`- **${el(ep.node)}** (${ep.type})`);
      for (const ib of ep.inbound) {
        out.push(
          `  - ${t('testPlan.scope.inbound', {
            id: ib.id,
            peer: el(ib.peer),
            auth: ib.auth,
            encryption: ib.encryption,
            network: ib.network,
          })}`,
        );
      }
    }
    out.push('');
  }

  // 3. 攻撃シナリオ
  out.push(`## ${t('testPlan.h.scenarios')}`, '');
  if (plan.scenarios.length === 0) {
    out.push(t('testPlan.scenarios.none'), '');
  }
  for (const sc of plan.scenarios) {
    out.push(`### ${t('testPlan.scenarios.heading', { attacker: el(sc.attacker), objective: el(sc.objective) })}`, '');
    if (sc.routes.length === 0) {
      out.push(t('testPlan.scenarios.noRoute'), '');
      continue;
    }
    out.push(`**${t('testPlan.scenarios.routes')}**`, '');
    sc.routes.forEach((r, i) => {
      const cost = r.cost === null ? t('testPlan.scenarios.blocked') : t('testPlan.scenarios.cost', { cost: r.cost });
      out.push(`${i + 1}. ${r.path.map((p) => p.id).join(' → ')}（${cost}）`);
      out.push(`   - ${r.path.map(el).join(' → ')}`);
      if (r.weakestHop) {
        out.push(`   - ${t('testPlan.scenarios.weakest', { from: r.weakestHop.from.id, to: r.weakestHop.to.id })}`);
      }
    });
    out.push('');
    if (sc.chokePoints.length > 0) {
      out.push(`**${t('testPlan.scenarios.chokePoints')}**`, '');
      for (const c of sc.chokePoints) {
        out.push(`- ${t('testPlan.scenarios.chokeHit', { label: c.label, hits: c.routeHits })}`);
      }
      out.push('');
    }
  }

  // 4. 重点テスト項目
  out.push(`## ${t('testPlan.h.focus')}`, '');
  if (plan.focusGroups.length === 0) out.push(t('testPlan.focus.none'), '');
  for (const g of plan.focusGroups) {
    out.push(`### ${el(g.target)}`, '');
    for (const th of g.threats) {
      out.push(`- **[${th.severity}] ${th.name}**（${th.ruleId}）`);
      out.push(`  - ${oneLine(th.description)}`);
    }
    out.push('');
    if (g.viewpoints.length === 0) {
      out.push(`_${t('testPlan.focus.noViewpoint')}_`, '');
    }
    for (const v of g.viewpoints) {
      out.push(`**${t('testPlan.focus.viewpoint', { title: v.title, threats: [...new Set(v.threatNames)].join(', ') })}**`, '');
      for (const c of v.checks) out.push(`- [ ] ${oneLine(c)}`);
      if (v.references.length > 0) {
        out.push('', t('testPlan.focus.references', { refs: v.references.map((r) => `${r.standard} ${r.id}`).join(', ') }));
      }
      out.push('');
    }
  }

  // 5. 対象外とする脅威
  out.push(`## ${t('testPlan.h.outOfScope')}`, '');
  if (plan.suppressed.length === 0) out.push(t('testPlan.outOfScope.none'), '');
  else {
    for (const s of plan.suppressed) {
      const status = t(s.status === 'false-positive' ? 'testPlan.status.false-positive' : 'testPlan.status.accepted');
      const note = s.note ? t('testPlan.outOfScope.note', { note: oneLine(s.note) }) : t('testPlan.outOfScope.noNote');
      out.push(`- ${el(s.target)}: [${s.severity}] ${s.name}（${s.ruleId}）— ${status}. ${note}`);
    }
    out.push('');
  }

  return `${out.join('\n').trimEnd()}\n`;
}

/** JSON は TestPlan をそのまま出す（キーは英語）。 */
export function testPlanToJson(plan: TestPlan): string {
  return JSON.stringify(plan, null, 2);
}
