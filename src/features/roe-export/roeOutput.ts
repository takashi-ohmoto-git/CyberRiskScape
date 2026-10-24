import { translate, type TranslationKey } from '../../i18n';
import type { RoeDocument, RoeScopeEntry } from './buildRoe';

/** 脅威モデルから作った交戦規定（RoE）／スコープ宣言を Markdown / JSON に整形する。 */

const ZONE_KEY: Record<RoeScopeEntry['zone'], TranslationKey> = {
  Internal: 'roe.zone.internal',
  Partner: 'roe.zone.partner',
  Internet: 'roe.zone.internet',
  Undeclared: 'roe.zone.undeclared',
};

const REASON_KEY: Record<string, TranslationKey> = {
  thirdParty: 'roe.reason.thirdParty',
  partnerZone: 'roe.reason.partnerZone',
  internetZone: 'roe.reason.internetZone',
};

export function roeToMarkdown(doc: RoeDocument): string {
  const t = (key: TranslationKey, params?: Record<string, string | number>) =>
    translate(key, doc.locale, params);
  const out: string[] = [];

  out.push(`# ${t('roe.title', { system: doc.system })}`, '');

  // 1. 概要と前提
  out.push(`## ${t('roe.h.overview')}`, '');
  out.push(`- ${t('roe.overview.system', { system: doc.system })}`);
  out.push(`- ${t('roe.overview.layer', { layer: doc.layer })}`);
  out.push(`- ${t('roe.overview.generated', { date: doc.generatedAt, product: doc.product })}`, '');
  out.push(`> ${t('roe.overview.purpose')}`, '');
  out.push(t('roe.overview.note'), '');

  // 2. 許可された対象（in-scope）
  out.push(`## ${t('roe.h.inScope')}`, '');
  if (doc.inScope.length === 0) {
    out.push(t('roe.inScope.none'), '');
  } else {
    out.push(t('roe.inScope.rule'), '');
    for (const e of doc.inScope) {
      const hint = e.addressHint
        ? ` — ${t('roe.addressHint', { hint: e.addressHint })}`
        : ` — ${t('roe.addressNone')}`;
      const undeclared = e.reason === 'undeclared' ? ` ${t('roe.inScope.undeclared')}` : '';
      out.push(`- **${`${e.id} ${e.name}`.trim()}** (${e.type}, ${t(ZONE_KEY[e.zone])})${hint}${undeclared}`);
    }
    out.push('');
  }

  // 3. スコープ外の対象（out-of-scope）
  out.push(`## ${t('roe.h.outOfScope')}`, '');
  out.push(t('roe.outOfScope.rule'), '');
  if (doc.outOfScope.length > 0) {
    for (const e of doc.outOfScope) {
      const reason = REASON_KEY[e.reason];
      out.push(
        `- **${`${e.id} ${e.name}`.trim()}** (${e.type})${reason ? ` — ${t(reason)}` : ''}`,
      );
    }
  }
  out.push('', t('roe.outOfScope.everythingElse'), '');

  // 4. 承認方針
  out.push(`## ${t('roe.h.approval')}`, '');
  out.push(t('roe.approval.intro'), '');
  for (const item of doc.approvalPolicy) {
    const mark = item.backed ? ` ${t('roe.approval.backed')}` : '';
    out.push(`- ${t(item.text as TranslationKey)}${mark}`);
  }
  out.push('');

  // 5. 送信元へ写す項目（運用者チェックリスト）
  out.push(`## ${t('roe.h.sourceSide')}`, '');
  out.push(t('roe.sourceSide.intro'), '');
  for (const k of [1, 2, 3, 4] as const) out.push(`- [ ] ${t(`roe.sourceSide.item${k}`)}`);
  out.push('');

  // 6. 限界
  out.push(`## ${t('roe.h.limits')}`, '');
  for (const k of [1, 2, 3] as const) out.push(`- ${t(`roe.limits.item${k}`)}`);
  out.push('');

  return out.join('\n');
}

export function roeToJson(doc: RoeDocument): string {
  return JSON.stringify(doc, null, 2);
}
