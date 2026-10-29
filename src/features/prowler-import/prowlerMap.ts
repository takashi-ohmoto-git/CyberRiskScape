import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import { POSTURE_FIELD_VALUES, type PostureEnumKey } from '../../core/model/types';

/**
 * Prowler の検査 ID → 図の属性・canonicalId の対応表（`data/finding-maps/prowler.yaml`）。
 * 脅威知識はコードに置かず YAML に置く。値の良し悪しの順序だけはここ 1 か所で定義する。
 */

export type FieldValue = string | boolean;

/**
 * 取り込みで扱う項目の値を、**悪い順 → 良い順**に並べたもの（順序の定義はここだけ）。
 * キーは運用状況の項目名、または `attackSurface.<項目名>`。この表にない項目は対応表に書けない。
 * 運用状況の値は `POSTURE_FIELD_VALUES`（列挙の一次ソース）と同じ集合であることをテストで確かめる。
 */
export const FIELD_VALUE_ORDER: Readonly<Record<string, readonly FieldValue[]>> = {
  encryptionAtRest: ['None', 'ProviderManagedKey', 'CustomerManagedKey'],
  logCollection: ['NotCollected', 'Collected'],
  logRetention: ['Under90Days', 'Under1Year', 'OneYearOrMore'],
  patchStatus: ['Missing', 'UpToDate'],
  accountReview: ['None', 'Irregular', 'Periodic'],
  'attackSurface.hasAccessLog': [false, true],
  'attackSurface.hasGlobalIp': [true, false],
};

const ATTACK_SURFACE_PREFIX = 'attackSurface.';

/** `attackSurface.xxx` なら項目名 xxx、運用状況の項目なら undefined。 */
export function attackSurfaceKeyOf(field: string): string | undefined {
  return field.startsWith(ATTACK_SURFACE_PREFIX) ? field.slice(ATTACK_SURFACE_PREFIX.length) : undefined;
}

/** a と b のうち悪い方（同順位は a）。 */
export function worseValue(field: string, a: FieldValue, b: FieldValue): FieldValue {
  const order = FIELD_VALUE_ORDER[field] ?? [];
  return order.indexOf(b) < order.indexOf(a) ? b : a;
}

/** a と b のうち良い方（同順位は a）。 */
export function betterValue(field: string, a: FieldValue, b: FieldValue): FieldValue {
  const order = FIELD_VALUE_ORDER[field] ?? [];
  return order.indexOf(b) > order.indexOf(a) ? b : a;
}

const ProwlerMapSchema = z.object({
  schemaVersion: z.literal(1),
  mappings: z.array(
    z.object({
      checks: z.array(z.string().min(1)).nonempty(),
      set: z
        .object({
          field: z.string().min(1),
          pass: z.union([z.string(), z.boolean()]).optional(),
          fail: z.union([z.string(), z.boolean()]).optional(),
          /** PASS の ProviderManagedKey が鍵の種類（AWS 管理鍵か CMK か）を判別できない検査に付ける。 */
          keyTypeUnverified: z.boolean().optional(),
        })
        .optional(),
      canonicalIds: z.array(z.string().min(1)).optional(),
      note: z.string().optional(),
    }),
  ),
});

export type ProwlerMapping = z.infer<typeof ProwlerMapSchema>['mappings'][number];

function validateSet(set: NonNullable<ProwlerMapping['set']>, where: string): void {
  const order = FIELD_VALUE_ORDER[set.field];
  if (!order) throw new Error(`[prowler-map] ${where}: 未対応の項目 ${set.field}`);
  if (set.pass === undefined && set.fail === undefined) {
    throw new Error(`[prowler-map] ${where}: set に pass も fail もありません`);
  }
  if (set.keyTypeUnverified && (set.field !== 'encryptionAtRest' || set.pass !== 'ProviderManagedKey')) {
    throw new Error(`[prowler-map] ${where}: keyTypeUnverified は encryptionAtRest の pass: ProviderManagedKey にだけ付けられます`);
  }
  const posture = set.field in POSTURE_FIELD_VALUES ? POSTURE_FIELD_VALUES[set.field as PostureEnumKey] : undefined;
  for (const v of [set.pass, set.fail]) {
    if (v === undefined) continue;
    if (!order.includes(v)) throw new Error(`[prowler-map] ${where}: ${set.field} に不正な値 ${String(v)}`);
    if (posture && !(posture as readonly string[]).includes(v as string)) {
      throw new Error(`[prowler-map] ${where}: ${set.field} は列挙に無い値 ${String(v)}`);
    }
  }
}

export function loadProwlerMap(text: string): ProwlerMapping[] {
  const mappings = ProwlerMapSchema.parse(parseYaml(text)).mappings;
  const seen = new Set<string>();
  for (const m of mappings) {
    for (const c of m.checks) {
      if (seen.has(c)) throw new Error(`[prowler-map] 検査 ${c} が複数のエントリに載っています`);
      seen.add(c);
    }
    if (m.set) validateSet(m.set, m.checks[0]);
  }
  return mappings;
}

/** 検査 ID → 対応表のエントリ。載っていなければ undefined。 */
export function findProwlerMapping(mappings: readonly ProwlerMapping[], checkId: string): ProwlerMapping | undefined {
  return mappings.find((m) => m.checks.includes(checkId));
}

// ── 同梱データ（Vite の import.meta.glob で raw 文字列として取り込む。CLI ビルド・Vitest でも動く）──

const sources = import.meta.glob<string>('../../../data/finding-maps/prowler.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const BUNDLED_PROWLER_MAP: ProwlerMapping[] = loadProwlerMap(
  Object.values(sources)[0] ?? 'schemaVersion: 1\nmappings: []\n',
);
