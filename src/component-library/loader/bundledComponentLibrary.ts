import { loadComponentLibraries, type LoadResult, type RawYamlFile } from './loadComponentLibrary';

/**
 * `data/component-library/*.yaml` をビルド時にバンドルし、起動時にロードする。
 * 仕組みは `threat-library/loader/bundledLibrary.ts` と同様。
 */
const yamlModules = import.meta.glob<string>('../../../data/component-library/*.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

const files: RawYamlFile[] = Object.entries(yamlModules).map(([path, text]) => ({
  source: path.split('/').pop() ?? path,
  text,
}));

export const BUNDLED_COMPONENT_LIBRARY: LoadResult = loadComponentLibraries(files);

// 起動時に warn ログ（開発時の検出を容易にする）
if (BUNDLED_COMPONENT_LIBRARY.warnings.length > 0) {
  for (const w of BUNDLED_COMPONENT_LIBRARY.warnings) {
    console.warn(`[component-library] ${w}`);
  }
}
