import { loadComponentOverlay } from './localizeComponentLibrary';
import type { RawYamlFile } from './loadComponentLibrary';
import type { ComponentOverlayMap } from '../schema/componentOverlay';

/**
 * コンポーネント型の翻訳オーバーレイ（`data/component-library/i18n/<locale>/*.yaml`）。
 *
 * 原本とは別ファイルに置き、`ComponentDefinition` のスキーマは変更しない。
 * 原本と同じくビルド時にバンドルし、**起動時にパース・検証**する
 * （壊れたオーバーレイを言語切替のタイミングまで気付かないのを避けるため）。
 */
const overlayModules = import.meta.glob<string>('../../../data/component-library/i18n/*/*.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

const filesByLocale: Record<string, RawYamlFile[]> = {};
for (const [path, text] of Object.entries(overlayModules)) {
  const segments = path.split('/');
  const fileName = segments[segments.length - 1] ?? path;
  const locale = segments[segments.length - 2] ?? '';
  (filesByLocale[locale] ??= []).push({ source: `${locale}/${fileName}`, text });
}

export const BUNDLED_COMPONENT_OVERLAYS: Record<string, ComponentOverlayMap> = Object.fromEntries(
  Object.entries(filesByLocale).map(([locale, files]) => [locale, loadComponentOverlay(files)]),
);
