import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import type { Locale } from '../../i18n';

/**
 * 検出した脅威 → 検証用リクエストの対応表（`data/test-templates/postman.yaml`）。
 * 原本は日本語、`i18n/en/postman.yaml` は name / purpose / 変数の説明だけを上書きする翻訳オーバーレイ。
 */

const HeaderSchema = z.object({ key: z.string().min(1), value: z.string() });

const TestTemplateSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  match: z.object({ canonicalIds: z.array(z.string().min(1)).nonempty() }),
  name: z.string().min(1),
  purpose: z.string().min(1),
  variables: z
    .array(z.object({ key: z.string().min(1), value: z.string(), description: z.string().optional() }))
    .optional(),
  request: z.object({
    method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']),
    url: z.string().min(1),
    headers: z.array(HeaderSchema).optional(),
    body: z.string().optional(),
  }),
  tests: z.string().min(1),
});

const TestTemplateFileSchema = z.object({
  schemaVersion: z.literal(1),
  templates: z.array(TestTemplateSchema),
});

const OverlaySchema = z.object({
  schemaVersion: z.literal(1),
  locale: z.string(),
  templates: z.record(
    z.object({
      name: z.string().optional(),
      purpose: z.string().optional(),
      variables: z.record(z.string()).optional(),
    }),
  ),
});

export type TestTemplate = z.infer<typeof TestTemplateSchema>;

export function loadTestTemplates(text: string): TestTemplate[] {
  const templates = TestTemplateFileSchema.parse(parseYaml(text)).templates;
  const ids = templates.map((t) => t.id);
  const dup = ids.find((id, i) => ids.indexOf(id) !== i);
  if (dup) throw new Error(`[test-templates] duplicate template id "${dup}"`);
  return templates;
}

/** 翻訳オーバーレイを当てる（無いキーは原本のまま）。 */
export function localizeTestTemplates(templates: TestTemplate[], overlayText: string): TestTemplate[] {
  const overlay = OverlaySchema.parse(parseYaml(overlayText)).templates;
  return templates.map((t) => {
    const o = overlay[t.id];
    if (!o) return t;
    return {
      ...t,
      name: o.name ?? t.name,
      purpose: o.purpose ?? t.purpose,
      variables: t.variables?.map((v) => ({ ...v, description: o.variables?.[v.key] ?? v.description })),
    };
  });
}

// ── 同梱データ（Vite の import.meta.glob で raw 文字列として取り込む。CLI ビルド・Vitest でも動く）──

const sources = import.meta.glob<string>('../../../data/test-templates/postman.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});
const overlays = import.meta.glob<string>('../../../data/test-templates/i18n/*/postman.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

const BUNDLED = loadTestTemplates(Object.values(sources)[0] ?? 'schemaVersion: 1\ntemplates: []\n');

export function getTestTemplates(locale: Locale): TestTemplate[] {
  if (locale === 'ja') return BUNDLED;
  const overlay = Object.entries(overlays).find(([path]) => path.includes(`/i18n/${locale}/`))?.[1];
  return overlay ? localizeTestTemplates(BUNDLED, overlay) : BUNDLED;
}
