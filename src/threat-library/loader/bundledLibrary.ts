import { loadThreatLibrary, type LoadResult, type RawYamlFile } from './loadThreatLibrary';
import {
  findOrphanOverlayIds,
  findUntranslatedRuleIds,
  loadThreatLibraryOverlay,
  localizeRules,
} from './localizeThreatLibrary';
import type { ThreatRuleOverlayMap } from '../schema/threatRuleOverlay';
import type { Locale } from '../../i18n';
import { componentRegistry } from '../../component-library/defaultRegistry';
import { collectReferencedNodeTypes } from './validateNodeTypeReferences';

/**
 * `data/threat-library/*.yaml` をビルド時にバンドルし、起動時にロードする。
 *
 * Vite の `import.meta.glob` で raw 文字列として取り込み、共通の
 * `loadThreatLibrary` に通すことでスキーマ違反や id 重複を起動時点で検出する。
 *
 * ライブラリは tiny（数十ルール想定）なので eager で問題ない。
 * サイズが膨らんだ際は `eager: false` に切り替え、初回描画前に await する。
 */
const yamlModules = import.meta.glob<string>('../../../data/threat-library/*.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

const files: RawYamlFile[] = Object.entries(yamlModules).map(([path, text]) => ({
  // パス末尾のファイル名のみを source として使う（エラーメッセージの見やすさ重視）
  source: path.split('/').pop() ?? path,
  text,
}));

export const BUNDLED_THREAT_LIBRARY: LoadResult = loadThreatLibrary(files);

// 脅威ルールが参照する nodeType が ComponentRegistry に登録済みかを起動時に検証。
// dangling は warn のみで実行は止めない（カスタムライブラリ無効化中の運用も許容）。
for (const { ruleId, nodeType } of collectReferencedNodeTypes(BUNDLED_THREAT_LIBRARY.rules)) {
  if (!componentRegistry.has(nodeType)) {
    console.warn(
      `[threat-library] Rule "${ruleId}" references unknown component type "${nodeType}". The rule will never fire until a component library declares this type.`,
    );
  }
}

/**
 * 翻訳オーバーレイ（`data/threat-library/i18n/<locale>/*.yaml`）。
 *
 * 原本（日本語）とは別ファイルに置き、`ThreatRule` のスキーマは変更しない。
 * 原本と同じくビルド時にバンドルし、**起動時にパース・検証**する（壊れた
 * オーバーレイを言語切替のタイミングまで気付かないのを避けるため）。
 */
const overlayModules = import.meta.glob<string>('../../../data/threat-library/i18n/*/*.yaml', {
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

const OVERLAYS: Record<string, ThreatRuleOverlayMap> = Object.fromEntries(
  Object.entries(overlayFilesByLocale).map(([locale, files]) => [
    locale,
    loadThreatLibraryOverlay(files),
  ]),
);

// 訳が原本と食い違っていないかを起動時に診断（warn のみ。実行は止めない）。
for (const [locale, overlay] of Object.entries(OVERLAYS)) {
  const orphans = findOrphanOverlayIds(BUNDLED_THREAT_LIBRARY.rules, overlay);
  if (orphans.length > 0) {
    console.warn(
      `[threat-library] Overlay "${locale}" translates ${orphans.length} rule(s) that no longer exist: ${orphans.join(', ')}`,
    );
  }
  const untranslated = findUntranslatedRuleIds(BUNDLED_THREAT_LIBRARY.rules, overlay);
  if (untranslated.length > 0) {
    console.warn(
      `[threat-library] Overlay "${locale}" is missing ${untranslated.length} of ${BUNDLED_THREAT_LIBRARY.rules.length} rules; those fall back to the original text.`,
    );
  }
}

const localizedCache = new Map<string, LoadResult>();

/**
 * 指定ロケールの脅威ライブラリを返す。訳が無いルール・フィールドは原文のまま。
 *
 * `ja` は原本そのものを返す（コピーもマージも発生しない）。他ロケールは
 * 初回呼び出し時にだけ合成し、以降はキャッシュを返す。
 */
export function getThreatLibrary(locale: Locale): LoadResult {
  if (locale === 'ja') return BUNDLED_THREAT_LIBRARY;

  const cached = localizedCache.get(locale);
  if (cached) return cached;

  const overlay = OVERLAYS[locale];
  const result: LoadResult = overlay
    ? { ...BUNDLED_THREAT_LIBRARY, rules: localizeRules(BUNDLED_THREAT_LIBRARY.rules, overlay) }
    : BUNDLED_THREAT_LIBRARY;

  localizedCache.set(locale, result);
  return result;
}
