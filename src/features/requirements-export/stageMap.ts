import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import type { Locale } from '../../i18n';

/**
 * 脅威 → 要件が効く工程、および委託先へ求める要件の対応表（`data/requirement-maps/process-stages.yaml`）。
 * 原本は日本語、`i18n/en/process-stages.yaml` は stageLabels / contractorRequirements.text だけを上書きする翻訳オーバーレイ。
 */

export const STAGES = ['design', 'implementation', 'verification', 'operation'] as const;
export type Stage = (typeof STAGES)[number];

const StageSchema = z.enum(STAGES);

const ContractorRequirementSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  triggers: z.array(z.string().min(1)).nonempty(),
  text: z.string().min(1),
});

const StageLabelsSchema = z.object({
  design: z.string().min(1),
  implementation: z.string().min(1),
  verification: z.string().min(1),
  operation: z.string().min(1),
});

const StageMapFileSchema = z.object({
  schemaVersion: z.literal(1),
  stageLabels: StageLabelsSchema,
  default: z.array(StageSchema).nonempty(),
  stages: z.record(z.string(), z.array(StageSchema).nonempty()),
  contractorRequirements: z.array(ContractorRequirementSchema),
});

const OverlaySchema = z.object({
  schemaVersion: z.literal(1),
  locale: z.string(),
  stageLabels: StageLabelsSchema.partial().optional(),
  contractorRequirements: z.record(z.string(), z.object({ text: z.string().min(1).optional() })).optional(),
});

export type ContractorRequirementDef = z.infer<typeof ContractorRequirementSchema>;
export type StageMap = z.infer<typeof StageMapFileSchema>;

export function loadStageMap(text: string): StageMap {
  const map = StageMapFileSchema.parse(parseYaml(text));
  const ids = map.contractorRequirements.map((c) => c.id);
  const dup = ids.find((id, i) => ids.indexOf(id) !== i);
  if (dup) throw new Error(`[requirement-maps] duplicate contractor requirement id "${dup}"`);
  return map;
}

/** 翻訳オーバーレイを当てる（無いキーは原本のまま）。 */
export function localizeStageMap(map: StageMap, overlayText: string): StageMap {
  const o = OverlaySchema.parse(parseYaml(overlayText));
  return {
    ...map,
    stageLabels: { ...map.stageLabels, ...o.stageLabels },
    contractorRequirements: map.contractorRequirements.map((c) => ({
      ...c,
      text: o.contractorRequirements?.[c.id]?.text ?? c.text,
    })),
  };
}

// ── 同梱データ（Vite の import.meta.glob で raw 文字列として取り込む。CLI ビルド・Vitest でも動く）──

const sources = import.meta.glob<string>('../../../data/requirement-maps/process-stages.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});
const overlays = import.meta.glob<string>('../../../data/requirement-maps/i18n/*/process-stages.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

const EMPTY = `schemaVersion: 1
stageLabels: { design: 設計, implementation: 実装, verification: 検証, operation: 運用 }
default: [design]
stages: {}
contractorRequirements: []
`;

const BUNDLED = loadStageMap(Object.values(sources)[0] ?? EMPTY);

/** 英語オーバーレイの生テキスト（テスト用）。 */
export const BUNDLED_STAGE_OVERLAY_EN: string | undefined = Object.entries(overlays).find(([path]) =>
  path.includes('/i18n/en/'),
)?.[1];

export function getStageMap(locale: Locale): StageMap {
  if (locale === 'ja') return BUNDLED;
  const overlay = Object.entries(overlays).find(([path]) => path.includes(`/i18n/${locale}/`))?.[1];
  return overlay ? localizeStageMap(BUNDLED, overlay) : BUNDLED;
}
