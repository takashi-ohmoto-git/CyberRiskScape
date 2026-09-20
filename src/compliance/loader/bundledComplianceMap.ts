import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';
import {
  findUnresolvedComplianceRefs,
  loadComplianceMap,
  type LoadedComplianceMap,
  type RawYamlFile,
} from './loadComplianceMap';
import {
  findOrphanOverlayRefs,
  loadComplianceOverlay,
  localizeComplianceMap,
} from './localizeComplianceMap';
import type { ComplianceOverlayMap } from '../schema/complianceOverlay';
import type { Locale } from '../../i18n';

/**
 * `data/compliance/*.yaml` をビルド時にバンドルし、起動時にロードする。
 *
 * 設計は `bundledLibrary.ts` と同等。脅威ライブラリ側 ref がマップに解決
 * できない場合は **warn ログのみ** とし、起動を妨げない（UI 側でフォールバック表示）。
 */
const yamlModules = import.meta.glob<string>('../../../data/compliance/*.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

const files: RawYamlFile[] = Object.entries(yamlModules).map(([path, text]) => ({
  source: path.split('/').pop() ?? path,
  text,
}));

export const BUNDLED_COMPLIANCE_MAP: LoadedComplianceMap = loadComplianceMap(files);

// 起動時の整合性チェック（warn ログ）。脅威ルール側に未解決の complianceRefs が
// 残っていても fail させない — マップ未収録 ref は UI 側でフォールバック表示するため。
const unresolved = findUnresolvedComplianceRefs(
  BUNDLED_COMPLIANCE_MAP,
  BUNDLED_THREAT_LIBRARY.rules,
);
if (unresolved.length > 0) {
  console.warn(
    `[compliance] ${unresolved.length} threat rule complianceRefs are not in the compliance map:\n` +
      unresolved
        .map((u) => `  - rule "${u.ruleId}" → ${u.standard} / ${u.ref}`)
        .join('\n'),
  );
}


/**
 * 翻訳オーバーレイ（`data/compliance/i18n/<locale>/*.yaml`）。
 *
 * 原本とは別ファイルに置き、`ComplianceItem` / `ComplianceStandard` の
 * スキーマは変更しない。原本と同じくビルド時にバンドルし、起動時に検証する。
 */
const overlayModules = import.meta.glob<string>('../../../data/compliance/i18n/*/*.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

const overlayFilesByLocale: Record<string, RawYamlFile[]> = {};
for (const [path, text] of Object.entries(overlayModules)) {
  const segments = path.split('/');
  const fileName = segments[segments.length - 1] ?? path;
  const locale = segments[segments.length - 2] ?? '';
  (overlayFilesByLocale[locale] ??= []).push({ source: `${locale}/${fileName}`, text });
}

const OVERLAYS: Record<string, ComplianceOverlayMap> = Object.fromEntries(
  Object.entries(overlayFilesByLocale).map(([locale, files]) => [
    locale,
    loadComplianceOverlay(files),
  ]),
);

// 訳が原本と食い違っていないかを起動時に診断（warn のみ。実行は止めない）。
for (const [locale, overlay] of Object.entries(OVERLAYS)) {
  const orphans = findOrphanOverlayRefs(BUNDLED_COMPLIANCE_MAP, overlay);
  if (orphans.length > 0) {
    console.warn(
      `[compliance] Overlay "${locale}" refers to ${orphans.length} standard(s)/ref(s) that are not in the map: ${orphans.join(', ')}`,
    );
  }
}

const localizedCache = new Map<string, LoadedComplianceMap>();

/**
 * 指定ロケールのコンプライアンスマップを返す。訳が無いものは原文のまま。
 *
 * `ja` は原本をそのまま返す（コピーもマージも発生しない）。
 * 脅威ライブラリの `getThreatLibrary(locale)` と同じ設計。
 */
export function getComplianceMap(locale: Locale): LoadedComplianceMap {
  if (locale === 'ja') return BUNDLED_COMPLIANCE_MAP;

  const cached = localizedCache.get(locale);
  if (cached) return cached;

  const overlay = OVERLAYS[locale];
  const result = overlay
    ? localizeComplianceMap(BUNDLED_COMPLIANCE_MAP, overlay)
    : BUNDLED_COMPLIANCE_MAP;

  localizedCache.set(locale, result);
  return result;
}
