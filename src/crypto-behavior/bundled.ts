import {
  localizeTermination,
  parseAlgorithmTable,
  parseTerminationFile,
  parseTerminationOverlayFile,
} from './loader';
import type { AlgorithmTable, TerminationBehavior, TerminationOverlay } from './schema';
import type { Locale } from '../i18n';

/**
 * `data/crypto-behavior/*.yaml` をビルド時にバンドルしてロードする
 * （`change-triggers/loader/bundledChangeTriggers.ts` と同じ設計）。
 */
const yamlModules = import.meta.glob<string>('../../data/crypto-behavior/*.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});
const overlayModules = import.meta.glob<string>('../../data/crypto-behavior/i18n/*/*.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

const textOf = (modules: Record<string, string>, suffix: string): string => {
  const entry = Object.entries(modules).find(([path]) => path.endsWith(suffix));
  if (!entry) throw new Error(`[crypto-behavior] missing data file: ${suffix}`);
  return entry[1];
};

export const BUNDLED_TERMINATION_BEHAVIORS: TerminationBehavior[] = parseTerminationFile(
  textOf(yamlModules, '/termination.yaml'),
  'termination.yaml',
);

export const BUNDLED_ALGORITHM_TABLE: AlgorithmTable = parseAlgorithmTable(
  textOf(yamlModules, '/pqc-algorithms.yaml'),
  'pqc-algorithms.yaml',
);

/** ロケール → 翻訳オーバーレイ（componentType → note）。 */
export const BUNDLED_TERMINATION_OVERLAYS: Record<string, TerminationOverlay> = {};
for (const [path, text] of Object.entries(overlayModules)) {
  const segments = path.split('/');
  if (segments[segments.length - 1] !== 'termination.yaml') continue;
  const locale = segments[segments.length - 2] ?? '';
  BUNDLED_TERMINATION_OVERLAYS[locale] = parseTerminationOverlayFile(
    text,
    `${locale}/termination.yaml`,
  );
}

const cache = new Map<string, TerminationBehavior[]>();

/** 指定ロケールの終端判定の既定値。訳が無い項目は原文（日本語）のまま。 */
export function getTerminationBehaviors(locale: Locale): TerminationBehavior[] {
  if (locale === 'ja') return BUNDLED_TERMINATION_BEHAVIORS;
  const cached = cache.get(locale);
  if (cached) return cached;
  const overlay = BUNDLED_TERMINATION_OVERLAYS[locale];
  const result = overlay
    ? localizeTermination(BUNDLED_TERMINATION_BEHAVIORS, overlay)
    : BUNDLED_TERMINATION_BEHAVIORS;
  cache.set(locale, result);
  return result;
}

/** 型の終端判定の既定値。YAML に無い型（端点）は undefined。 */
export function getTerminationBehavior(
  componentType: string,
  locale: Locale,
): TerminationBehavior | undefined {
  return getTerminationBehaviors(locale).find((b) => b.componentType === componentType);
}
