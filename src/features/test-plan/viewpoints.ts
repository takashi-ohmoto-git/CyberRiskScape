import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import type { Locale } from '../../i18n';

/**
 * 検出した脅威 → ペネトレーションテストの確認観点の対応表（`data/test-templates/pentest.yaml`）。
 * 原本は日本語、`i18n/en/pentest.yaml` は title / checks だけを上書きする翻訳オーバーレイ。
 */

const ViewpointSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  match: z.object({ canonicalIds: z.array(z.string().min(1)).nonempty() }),
  title: z.string().min(1),
  checks: z.array(z.string().min(1)).nonempty(),
  references: z.array(z.object({ standard: z.string().min(1), id: z.string().min(1) })),
});

const ViewpointFileSchema = z.object({
  schemaVersion: z.literal(1),
  viewpoints: z.array(ViewpointSchema),
});

const OverlaySchema = z.object({
  schemaVersion: z.literal(1),
  locale: z.string(),
  viewpoints: z.record(
    z.object({
      title: z.string().optional(),
      checks: z.array(z.string().min(1)).optional(),
    }),
  ),
});

export type PentestViewpoint = z.infer<typeof ViewpointSchema>;

export function loadViewpoints(text: string): PentestViewpoint[] {
  const viewpoints = ViewpointFileSchema.parse(parseYaml(text)).viewpoints;
  const ids = viewpoints.map((v) => v.id);
  const dup = ids.find((id, i) => ids.indexOf(id) !== i);
  if (dup) throw new Error(`[pentest-viewpoints] duplicate viewpoint id "${dup}"`);
  return viewpoints;
}

/** 翻訳オーバーレイを当てる（無いキーは原本のまま）。 */
export function localizeViewpoints(viewpoints: PentestViewpoint[], overlayText: string): PentestViewpoint[] {
  const overlay = OverlaySchema.parse(parseYaml(overlayText)).viewpoints;
  return viewpoints.map((v) => {
    const o = overlay[v.id];
    if (!o) return v;
    return { ...v, title: o.title ?? v.title, checks: (o.checks as [string, ...string[]] | undefined) ?? v.checks };
  });
}

// ── 同梱データ（Vite の import.meta.glob で raw 文字列として取り込む。CLI ビルド・Vitest でも動く）──

const sources = import.meta.glob<string>('../../../data/test-templates/pentest.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});
const overlays = import.meta.glob<string>('../../../data/test-templates/i18n/*/pentest.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

const BUNDLED = loadViewpoints(Object.values(sources)[0] ?? 'schemaVersion: 1\nviewpoints: []\n');

/** 英語オーバーレイの生テキスト（テスト用）。 */
export const BUNDLED_VIEWPOINT_OVERLAY_EN: string | undefined = Object.entries(overlays).find(([path]) =>
  path.includes('/i18n/en/'),
)?.[1];

export function getViewpoints(locale: Locale): PentestViewpoint[] {
  if (locale === 'ja') return BUNDLED;
  const overlay = Object.entries(overlays).find(([path]) => path.includes(`/i18n/${locale}/`))?.[1];
  return overlay ? localizeViewpoints(BUNDLED, overlay) : BUNDLED;
}
