import { loadThreatLibrary, type LoadResult, type RawYamlFile } from './loadThreatLibrary';
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
