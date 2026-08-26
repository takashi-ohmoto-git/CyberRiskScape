import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';
import {
  findUnresolvedComplianceRefs,
  loadComplianceMap,
  type LoadedComplianceMap,
  type RawYamlFile,
} from './loadComplianceMap';

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
  // eslint-disable-next-line no-console
  console.warn(
    `[compliance] ${unresolved.length} threat rule complianceRefs are not in the compliance map:\n` +
      unresolved
        .map((u) => `  - rule "${u.ruleId}" → ${u.standard} / ${u.ref}`)
        .join('\n'),
  );
}
