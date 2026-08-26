import { BUNDLED_COMPONENT_LIBRARY } from './loader/bundledComponentLibrary';
import { ComponentRegistry } from './registry';
import { isKnownBuiltinIcon } from './iconRegistry';

/**
 * アプリ起動時に確定するコンポーネントレジストリ。
 * ノード描画・パレット表示・脅威ルール整合性検証で共通利用する singleton。
 */
export const componentRegistry = new ComponentRegistry(BUNDLED_COMPONENT_LIBRARY);

// アイコン名の不整合検出（warn のみ・実行は止めない）
for (const comp of BUNDLED_COMPONENT_LIBRARY.components) {
  if (comp.icon.kind === 'builtin' && !isKnownBuiltinIcon(comp.icon.name)) {
    console.warn(
      `[component-library] Component "${comp.id}" uses unknown builtin icon "${comp.icon.name}" — will fall back to HelpCircle. Add it to BUILTIN_ICONS in iconRegistry.tsx.`,
    );
  }
}
