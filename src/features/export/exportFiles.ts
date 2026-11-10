import { LAYER_KEYS, type LayerKey, type ManualThreat } from '../../core/model/types';
import { formatLocalDate } from '../../core/model/localDate';
import { useDiagramStore } from '../../core/state/diagramStore';
import { useCustomRulesStore, selectCustomLibraries } from '../custom-rules/store';
import { mergeThreatRules } from '../custom-rules/mergeRules';
import { getThreatLibrary } from '../../threat-library/loader/bundledLibrary';
import { getLocale, translate } from '../../i18n';
import { buildMigrationReport, renderMigrationReportMarkdown } from '../tm7-import/migrationReport';
import { TM7_PRODUCT } from '../tm7-import/tm7ToProject';
import { buildThreatReport } from './threatReport';
import { computeLayerThreats } from './layerThreats';
import { triggerBlobDownload, triggerDownload } from './download';

/** レポートのファイル名（拡張子なし）。例: `threat-report_CreditScoringAPI_L1_2026-06-03`。 */
export function reportFilename(systemName: string, layer: string): string {
  const slug = systemName.trim().replace(/[^\w.-]+/g, '_').slice(0, 60);
  const date = formatLocalDate(new Date());
  return ['threat-report', slug, layer, date].filter(Boolean).join('_');
}

/** 現在のストア状態＋カスタムルールで、選択レイヤーごとの脅威を算出する（App.tsx と同経路）。 */
function collect(layerKeys: readonly LayerKey[]) {
  const state = useDiagramStore.getState();
  const locale = getLocale();
  const merged = mergeThreatRules(
    getThreatLibrary(locale).rules,
    selectCustomLibraries(useCustomRulesStore.getState()),
  );
  return { state, locale, items: computeLayerThreats(state, merged, layerKeys) };
}

/** 選択レイヤーごとに 1 ファイルの PNG をダウンロードする。ノードが無いレイヤーは出さない。 */
export async function exportPng(layerKeys: readonly LayerKey[]): Promise<void> {
  const { renderDiagramPng } = await import('./png/renderDiagramPng');
  const { state, items } = collect(layerKeys);
  for (const item of items) {
    const png = await renderDiagramPng(state.layers[item.layer], item.threats);
    if (!png) continue;
    triggerBlobDownload(`${reportFilename(state.projectMeta.systemName, item.layer)}.png`, png, 'image/png');
  }
}

/** 選択レイヤーをまとめた 1 本の PDF をダウンロードする。 */
export async function exportPdf(layerKeys: readonly LayerKey[]): Promise<void> {
  const [{ renderDiagramPng }, { buildPdfReport }, assets] = await Promise.all([
    import('./png/renderDiagramPng'),
    import('./pdf/buildPdfReport'),
    import('./exportAssets'),
  ]);
  const { state, locale, items } = collect(layerKeys);
  const reports = [];
  for (const item of items) {
    const diagramPng = await renderDiagramPng(state.layers[item.layer], item.threats);
    reports.push({
      layer: item.layer,
      report: buildThreatReport(item.input),
      threats: item.threats,
      diagramPng: diagramPng ?? undefined,
      layerData: state.layers[item.layer],
    });
  }
  const { fonts, harfbuzzWasm } = await assets.loadPdfAssets();
  const pdf = await buildPdfReport({
    reports,
    locale,
    generatedAt: new Date(),
    appVersion: assets.APP_VERSION,
    fonts,
    harfbuzzWasm,
  });
  triggerBlobDownload(
    `${reportFilename(state.projectMeta.systemName, layerKeys.join('-'))}.pdf`,
    pdf,
    'application/pdf',
  );
}

/** 手動脅威のうち Microsoft Threat Modeling Tool（.tm7）から取り込んだものが 1 件でもあるか。 */
export function hasTmtThreats(manualThreats: Record<LayerKey, ManualThreat[]>): boolean {
  return LAYER_KEYS.some((k) => manualThreats[k].some((m) => m.importedFrom?.product === TM7_PRODUCT));
}

/** TMT からの移行レポート（Markdown）をダウンロードする。framework は ALL で全脅威を対象にする。 */
export function exportMigrationReport(): void {
  const state = useDiagramStore.getState();
  const locale = getLocale();
  const merged = mergeThreatRules(
    getThreatLibrary(locale).rules,
    selectCustomLibraries(useCustomRulesStore.getState()),
  );
  const layerKeys = LAYER_KEYS.filter((k) => state.layers[k].nodes.length > 0);
  const items = computeLayerThreats({ ...state, activeFramework: 'ALL' }, merged, layerKeys);
  const report = buildMigrationReport({
    layers: items.map((i) => ({ layer: i.layer, threats: i.threats, nodes: i.input.nodes, edges: i.input.edges })),
    manualThreats: state.manualThreats,
  });
  const md = renderMigrationReportMarkdown(report, (key, params) => translate(key, locale, params));
  const slug = state.projectMeta.systemName.trim().replace(/[^\w.-]+/g, '_').slice(0, 60);
  const name = ['migration-report', slug, formatLocalDate(new Date())].filter(Boolean).join('_');
  triggerDownload(`${name}.md`, md, 'text/markdown;charset=utf-8');
}
