import { translate, type TranslationKey } from '../../i18n';
import type { RequirementsList } from './buildRequirements';
import { csvRow } from '../export/threatReport';

/**
 * セキュリティ要件一覧（RequirementsList）を Markdown / CSV / JSON に整形する。
 * CSV に BOM は付けない（Excel 向けの BOM はダウンロード時に付与する慣習。CLI は素の UTF-8）。
 */

type T = (key: TranslationKey, params?: Record<string, string | number>) => string;

const oneLine = (s: string) => s.replace(/\s+/g, ' ').trim();
const mdCell = (s: string) => oneLine(s).replace(/\|/g, '\\|');

function labels(list: RequirementsList) {
  const t: T = (key, params) => translate(key, list.locale, params);
  const targets = (r: RequirementsList['requirements'][number]) =>
    r.targets.map((n) => `${n.id} ${n.name}`.trim()).join(', ');
  const stages = (r: RequirementsList['requirements'][number]) => r.stages.map((s) => list.stageLabels[s]).join(' / ');
  const status = (r: RequirementsList['requirements'][number]) =>
    r.accepted
      ? r.acceptedNotes.length > 0
        ? t('requirements.accepted.note', { note: r.acceptedNotes.join(' / ') })
        : t('requirements.accepted')
      : '';
  return { t, targets, stages, status };
}

export function requirementsToMarkdown(list: RequirementsList): string {
  const { t, targets, stages, status } = labels(list);
  const out: string[] = [];
  out.push(`# ${t('requirements.title', { system: list.system, layer: list.layer })}`, '');
  out.push(`> ${t('requirements.disclaimer')}`, '');
  out.push(`- ${t('requirements.system', { system: list.system })}`);
  out.push(`- ${t('requirements.generated', { date: list.generatedAt, product: list.product })}`);
  out.push(`- ${t('requirements.howTo')}`, '');

  out.push(`## ${t('requirements.h.list')}`, '');
  if (list.requirements.length === 0) {
    out.push(t('requirements.none'), '');
  } else {
    const head = [
      'requirements.col.id',
      'requirements.col.tier',
      'requirements.col.text',
      'requirements.col.targets',
      'requirements.col.basis',
      'requirements.col.stage',
      'requirements.col.csf',
      'requirements.col.contractor',
      'requirements.col.status',
    ].map((k) => t(k as TranslationKey));
    out.push(`| ${head.join(' | ')} |`, `|${head.map(() => '---').join('|')}|`);
    for (const r of list.requirements) {
      out.push(
        `| ${[
          r.id,
          r.tier,
          r.text,
          targets(r),
          `${r.threats.join(', ')} (${r.maxSeverity})`,
          stages(r),
          r.csfRefs.join(', '),
          r.contractor ? t('requirements.yes') : '',
          status(r),
        ]
          .map(mdCell)
          .join(' | ')} |`,
      );
    }
    out.push('');
  }

  if (list.contractorRequirements.length > 0) {
    out.push(`## ${t('requirements.h.contractor')}`, '', t('requirements.contractor.lead'), '');
    for (const c of list.contractorRequirements) {
      out.push(`- ${oneLine(c.text)}（${t('requirements.contractor.basis', { threats: c.threats.join(', ') })}）`);
    }
    out.push('');
  }
  return out.join('\n');
}

export function requirementsToCsv(list: RequirementsList): string {
  const { t, targets, stages, status } = labels(list);
  const head = [
    'requirements.col.id',
    'requirements.col.tier',
    'requirements.col.text',
    'requirements.col.targets',
    'requirements.col.basis',
    'requirements.col.severity',
    'requirements.col.stage',
    'requirements.col.csf',
    'requirements.col.contractor',
    'requirements.col.status',
  ].map((k) => t(k as TranslationKey));
  const rows = list.requirements.map((r) =>
    csvRow([
      r.id,
      r.tier,
      oneLine(r.text),
      targets(r),
      r.threats.join(', '),
      r.maxSeverity,
      stages(r),
      r.csfRefs.join(', '),
      r.contractor ? t('requirements.yes') : '',
      status(r),
    ]),
  );
  return [csvRow(head), ...rows].join('\r\n') + '\r\n';
}

export function requirementsToJson(list: RequirementsList): string {
  return JSON.stringify(list, null, 2) + '\n';
}
