import { localizeChecklist, parseChecklistFile, parseChecklistOverlayFile } from './loader';
import type { Checklist, ChecklistOverlayFile } from './schema';
import type { Locale } from '../i18n';

/**
 * `data/checklists/*.yaml` をビルド時にバンドルしてロードする
 * （`crypto-behavior/bundled.ts` と同じ設計）。次の注意喚起は YAML を足すだけ。
 */
const yamlModules = import.meta.glob<string>('../../data/checklists/*.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});
const overlayModules = import.meta.glob<string>('../../data/checklists/i18n/*/*.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const BUNDLED_CHECKLISTS: Checklist[] = Object.entries(yamlModules)
  .map(([path, text]) => parseChecklistFile(text, path.split('/').pop() ?? path))
  .sort((a, b) => b.checklist.source.publishedAt.localeCompare(a.checklist.source.publishedAt));

/** ロケール → チェックリスト id → 翻訳オーバーレイ。 */
const overlays: Record<string, Record<string, ChecklistOverlayFile>> = {};
for (const [path, text] of Object.entries(overlayModules)) {
  const segments = path.split('/');
  const file = segments[segments.length - 1] ?? '';
  const locale = segments[segments.length - 2] ?? '';
  const overlay = parseChecklistOverlayFile(text, `${locale}/${file}`);
  (overlays[locale] ??= {})[file.replace(/\.yaml$/, '')] = overlay;
}

const cache = new Map<string, Checklist[]>();

/** 指定ロケールのチェックリスト一覧（新しい順）。訳が無い項目は原文のまま。 */
export function getChecklists(locale: Locale): Checklist[] {
  if (locale === 'ja') return BUNDLED_CHECKLISTS;
  const cached = cache.get(locale);
  if (cached) return cached;
  const result = BUNDLED_CHECKLISTS.map((c) => {
    const overlay = overlays[locale]?.[c.checklist.id];
    return overlay ? localizeChecklist(c, overlay) : c;
  });
  cache.set(locale, result);
  return result;
}

/** 翻訳オーバーレイのうち原本が無いもの（テスト用）。 */
export function findOrphanChecklistOverlays(locale: string): string[] {
  const ids = new Set(BUNDLED_CHECKLISTS.map((c) => c.checklist.id));
  return Object.keys(overlays[locale] ?? {}).filter((id) => !ids.has(id));
}
