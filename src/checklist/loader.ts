import { parse as parseYaml } from 'yaml';
import type { ZodType } from 'zod';
import {
  ChecklistFileSchema,
  ChecklistOverlayFileSchema,
  type Checklist,
  type ChecklistOverlayFile,
} from './schema';

/** チェックリスト YAML のロード失敗時に投げる例外。 */
export class ChecklistLoadError extends Error {
  readonly source: string;

  constructor(message: string, source: string) {
    super(message);
    this.name = 'ChecklistLoadError';
    this.source = source;
  }
}

function parseWith<T>(schema: ZodType<T>, yamlText: string, source: string): T {
  let parsed: unknown;
  try {
    parsed = parseYaml(yamlText);
  } catch (e) {
    throw new ChecklistLoadError(`YAML parse error in "${source}": ${(e as Error).message}`, source);
  }
  const result = schema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new ChecklistLoadError(`Schema validation failed for "${source}":\n${issues}`, source);
  }
  return result.data;
}

/** チェックリスト YAML をパース＋検証する。グループ id・項目 id の重複は throw。 */
export function parseChecklistFile(yamlText: string, source: string): Checklist {
  const file = parseWith(ChecklistFileSchema, yamlText, source);
  const groupIds = new Set<string>();
  const itemIds = new Set<string>();
  for (const g of file.groups) {
    if (groupIds.has(g.id)) throw new ChecklistLoadError(`Duplicate group id "${g.id}" in "${source}"`, source);
    groupIds.add(g.id);
    for (const item of g.items) {
      if (itemIds.has(item.id)) throw new ChecklistLoadError(`Duplicate item id "${item.id}" in "${source}"`, source);
      itemIds.add(item.id);
    }
  }
  return file;
}

/** 翻訳オーバーレイ YAML をパース＋検証する。 */
export function parseChecklistOverlayFile(yamlText: string, source: string): ChecklistOverlayFile {
  return parseWith(ChecklistOverlayFileSchema, yamlText, source);
}

/** 原本へオーバーレイを被せる。訳が無い項目は原文（日本語）のまま。 */
export function localizeChecklist(base: Checklist, overlay: ChecklistOverlayFile): Checklist {
  return {
    ...base,
    checklist: {
      ...base.checklist,
      title: overlay.checklist?.title ?? base.checklist.title,
      source: {
        ...base.checklist.source,
        publisher: overlay.checklist?.source?.publisher ?? base.checklist.source.publisher,
        title: overlay.checklist?.source?.title ?? base.checklist.source.title,
      },
    },
    groups: base.groups.map((g) => {
      const og = overlay.groups[g.id];
      if (!og) return g;
      return {
        ...g,
        title: og.title ?? g.title,
        items: g.items.map((item) => {
          const oi = og.items?.[item.id];
          return oi ? { ...item, title: oi.title ?? item.title, howTo: oi.howTo ?? item.howTo } : item;
        }),
      };
    }),
  };
}
