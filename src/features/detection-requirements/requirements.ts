import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import type { Locale } from '../../i18n';

/**
 * 検出した脅威 → 攻撃経路上で監視すべき振る舞い・必要なログの対応表（`data/detection-requirements/detection.yaml`）。
 * 原本は日本語、`i18n/en/detection.yaml` は title / watch / logs だけを上書きする翻訳オーバーレイ。
 * 「監視すべきこと」を示すだけで、検知できることを意味しない。
 */

const RequirementSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  match: z.object({ canonicalIds: z.array(z.string().min(1)).nonempty() }),
  title: z.string().min(1),
  watch: z.array(z.string().min(1)).min(1).max(4),
  logs: z.array(z.string().min(1)).nonempty(),
  /** 参考の ATT&CK テクニック ID。 */
  attack: z.array(z.string().regex(/^T\d{4}(\.\d{3})?$/)).optional(),
});

const RequirementFileSchema = z.object({
  schemaVersion: z.literal(1),
  requirements: z.array(RequirementSchema),
});

const OverlaySchema = z.object({
  schemaVersion: z.literal(1),
  locale: z.string(),
  requirements: z.record(
    z.object({
      title: z.string().optional(),
      watch: z.array(z.string().min(1)).optional(),
      logs: z.array(z.string().min(1)).optional(),
    }),
  ),
});

export type DetectionRequirement = z.infer<typeof RequirementSchema>;

export function loadDetectionRequirements(text: string): DetectionRequirement[] {
  const list = RequirementFileSchema.parse(parseYaml(text)).requirements;
  const ids = list.map((r) => r.id);
  const dup = ids.find((id, i) => ids.indexOf(id) !== i);
  if (dup) throw new Error(`[detection-requirements] duplicate requirement id "${dup}"`);
  const seen = new Map<string, string>();
  for (const r of list) {
    for (const c of r.match.canonicalIds) {
      const prev = seen.get(c);
      if (prev) throw new Error(`[detection-requirements] canonicalId "${c}" is in both "${prev}" and "${r.id}"`);
      seen.set(c, r.id);
    }
  }
  return list;
}

/** 翻訳オーバーレイを当てる（無いキーは原本のまま）。 */
export function localizeDetectionRequirements(list: DetectionRequirement[], overlayText: string): DetectionRequirement[] {
  const overlay = OverlaySchema.parse(parseYaml(overlayText)).requirements;
  return list.map((r) => {
    const o = overlay[r.id];
    if (!o) return r;
    return {
      ...r,
      title: o.title ?? r.title,
      watch: (o.watch as [string, ...string[]] | undefined) ?? r.watch,
      logs: (o.logs as [string, ...string[]] | undefined) ?? r.logs,
    };
  });
}

// ── 同梱データ（Vite の import.meta.glob で raw 文字列として取り込む。CLI ビルド・Vitest でも動く）──

const sources = import.meta.glob<string>('../../../data/detection-requirements/detection.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});
const overlays = import.meta.glob<string>('../../../data/detection-requirements/i18n/*/detection.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

const BUNDLED = loadDetectionRequirements(Object.values(sources)[0] ?? 'schemaVersion: 1\nrequirements: []\n');

/** 英語オーバーレイの生テキスト（テスト用）。 */
export const BUNDLED_DETECTION_OVERLAY_EN: string | undefined = Object.entries(overlays).find(([path]) =>
  path.includes('/i18n/en/'),
)?.[1];

export function getDetectionRequirements(locale: Locale): DetectionRequirement[] {
  if (locale === 'ja') return BUNDLED;
  const overlay = Object.entries(overlays).find(([path]) => path.includes(`/i18n/${locale}/`))?.[1];
  return overlay ? localizeDetectionRequirements(BUNDLED, overlay) : BUNDLED;
}
