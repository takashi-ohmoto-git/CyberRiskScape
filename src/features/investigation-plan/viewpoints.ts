import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import type { Locale } from '../../i18n';

/**
 * 検出した脅威 → 侵害調査の観点の対応表（`data/investigation-templates/compromise.yaml`）。
 * 原本は日本語、`i18n/en/compromise.yaml` は title / checks / logs だけを上書きする翻訳オーバーレイ。
 */

const ToolStepSchema = z.object({
  artifact: z.string().min(1),
  parameters: z.record(z.string()).optional(),
});

/** `tools/triage/crs_triage.py` に渡すパターン（`export-triage-patterns` で JSON に書き出す）。 */
const TriageSchema = z.object({
  logPatterns: z
    .array(
      z.object({
        id: z.string().min(1),
        category: z.string().min(1),
        regex: z.string().min(1),
        priority: z.number(),
      }),
    )
    .nonempty(),
  accessLog: z.object({ method: z.string().min(1), statuses: z.array(z.number().int().min(100).max(599)).nonempty() }).optional(),
  webroot: z.object({ extensions: z.array(z.string().min(1)), filenames: z.array(z.string().min(1)) }).optional(),
  notes: z.array(z.string().min(1)).optional(),
});

const ViewpointSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  match: z.object({ canonicalIds: z.array(z.string().min(1)).nonempty() }),
  title: z.string().min(1),
  checks: z.array(z.string().min(1)).nonempty(),
  logs: z.array(z.string().min(1)).nonempty(),
  /** ツール名 → 手がかり。`--tool` で選ばれたときだけ出力に載せる。 */
  tools: z
    .object({
      velociraptor: z.array(ToolStepSchema).nonempty().optional(),
      /** `--tool` では選ばれない。`export-triage-patterns` だけが読む。 */
      triage: TriageSchema.optional(),
    })
    .strict()
    .optional(),
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
      logs: z.array(z.string().min(1)).optional(),
    }),
  ),
});

export type InvestigationViewpoint = z.infer<typeof ViewpointSchema>;
export type TriageDefinition = z.infer<typeof TriageSchema>;
export type InvestigationToolStep = z.infer<typeof ToolStepSchema>;

export function loadInvestigationViewpoints(text: string): InvestigationViewpoint[] {
  const viewpoints = ViewpointFileSchema.parse(parseYaml(text)).viewpoints;
  const ids = viewpoints.map((v) => v.id);
  const dup = ids.find((id, i) => ids.indexOf(id) !== i);
  if (dup) throw new Error(`[investigation-viewpoints] duplicate viewpoint id "${dup}"`);
  return viewpoints;
}

/** 翻訳オーバーレイを当てる（無いキーは原本のまま）。 */
export function localizeInvestigationViewpoints(
  viewpoints: InvestigationViewpoint[],
  overlayText: string,
): InvestigationViewpoint[] {
  const overlay = OverlaySchema.parse(parseYaml(overlayText)).viewpoints;
  return viewpoints.map((v) => {
    const o = overlay[v.id];
    if (!o) return v;
    return {
      ...v,
      title: o.title ?? v.title,
      checks: (o.checks as [string, ...string[]] | undefined) ?? v.checks,
      logs: (o.logs as [string, ...string[]] | undefined) ?? v.logs,
    };
  });
}

// ── 同梱データ（Vite の import.meta.glob で raw 文字列として取り込む。CLI ビルド・Vitest でも動く）──

const sources = import.meta.glob<string>('../../../data/investigation-templates/compromise.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});
const overlays = import.meta.glob<string>('../../../data/investigation-templates/i18n/*/compromise.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

const BUNDLED = loadInvestigationViewpoints(Object.values(sources)[0] ?? 'schemaVersion: 1\nviewpoints: []\n');

/** 英語オーバーレイの生テキスト（テスト用）。 */
export const BUNDLED_INVESTIGATION_OVERLAY_EN: string | undefined = Object.entries(overlays).find(([path]) =>
  path.includes('/i18n/en/'),
)?.[1];

export function getInvestigationViewpoints(locale: Locale): InvestigationViewpoint[] {
  if (locale === 'ja') return BUNDLED;
  const overlay = Object.entries(overlays).find(([path]) => path.includes(`/i18n/${locale}/`))?.[1];
  return overlay ? localizeInvestigationViewpoints(BUNDLED, overlay) : BUNDLED;
}
