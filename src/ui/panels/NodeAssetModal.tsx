import { useEffect, useMemo, useState } from 'react';
import { Globe, Maximize2, Minimize2, X } from 'lucide-react';
import { useDiagramStore } from '../../core/state/diagramStore';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import { formatElementalId } from '../../core/model/elementalId';
import type { AssetSubject, BomComponent, BomKind, DiagramNode, LayerKey } from '../../core/model/types';
import { LAYER_KEYS } from '../../core/model/types';
import { buildNodeAssetViews, type AssetViews } from '../../features/asset-view/buildAssetViews';
import { listBomComponents } from '../../features/bom-import/listBomComponents';
import { useT, type TranslationKey } from '../../i18n';
import { AssetViewBody, MODE_LABEL_KEYS, type AssetMode, type ResolvedNode } from './AssetView';

/**
 * ノードに結びついた資産のポップアップ（docs/node-address-asset-panel.md §3.1）。読み取り専用。
 * 表示部は props だけで描ける NodeAssetModalBody に分け、テストしやすくしている。
 * 部品表は種類ごとにタブを分ける：SBOM（ソフトウェア・その他）／AI BOM（AI モデル・データセット）／CBOM（暗号）。
 */

export function countAssetViews(views: AssetViews): Record<AssetMode, number> {
  return {
    hosts: views.hosts.length,
    requests: views.requests.length,
    apis: views.apis.reduce((n, g) => n + g.endpoints.length, 0),
    sbom: views.sbom.length,
  };
}

/** ポップアップのタブ。部品表（Asset タブでは sbom 1 つ）を種類で 3 つに分ける。 */
export type NodeAssetMode = AssetMode | 'aibom' | 'cbom';
const NODE_MODES: NodeAssetMode[] = ['hosts', 'requests', 'apis', 'sbom', 'aibom', 'cbom'];

const BOM_TAB_KINDS: Record<'sbom' | 'aibom' | 'cbom', readonly BomKind[]> = {
  sbom: ['software', 'other'],
  aibom: ['ai-model', 'dataset'],
  cbom: ['crypto'],
};

const NODE_MODE_LABEL_KEYS: Record<NodeAssetMode, TranslationKey> = {
  hosts: MODE_LABEL_KEYS.hosts,
  requests: MODE_LABEL_KEYS.requests,
  apis: MODE_LABEL_KEYS.apis,
  sbom: MODE_LABEL_KEYS.sbom,
  aibom: 'panels.node.assets.mode.aibom',
  cbom: 'panels.node.assets.mode.cbom',
};

const isBomTab = (m: NodeAssetMode): m is 'sbom' | 'aibom' | 'cbom' => m in BOM_TAB_KINDS;

/** 部品を種類でタブに振り分ける（SBOM・AI BOM・CBOM）。純関数。 */
export function bomForTab(sbom: readonly BomComponent[], tab: 'sbom' | 'aibom' | 'cbom'): BomComponent[] {
  return sbom.filter((c) => BOM_TAB_KINDS[tab].includes(c.kind));
}

export function countNodeAssetModes(views: AssetViews): Record<NodeAssetMode, number> {
  const base = countAssetViews(views);
  return {
    hosts: base.hosts,
    requests: base.requests,
    apis: base.apis,
    sbom: bomForTab(views.sbom, 'sbom').length,
    aibom: bomForTab(views.sbom, 'aibom').length,
    cbom: bomForTab(views.sbom, 'cbom').length,
  };
}

export interface NodeAssetModalBodyProps {
  title: string;
  views: AssetViews;
  mode: NodeAssetMode;
  onModeChange: (m: NodeAssetMode) => void;
  resolve: (subject: AssetSubject | undefined) => ResolvedNode | null;
}

export function NodeAssetModalBody({ title, views, mode, onModeChange, resolve }: NodeAssetModalBodyProps) {
  const t = useT();
  const counts = countNodeAssetModes(views);
  const isEmpty = NODE_MODES.every((m) => counts[m] === 0);
  // 部品表のタブは、その種類の部品だけを載せた views を sbom の表で描く
  const bodyViews = isBomTab(mode) ? { ...views, sbom: bomForTab(views.sbom, mode) } : views;
  const bodyMode: AssetMode = isBomTab(mode) ? 'sbom' : mode;
  return (
    <div className="flex flex-col gap-4 min-h-0">
      <h2 className="text-sm font-bold text-slate-200">{title}</h2>
      {isEmpty ? (
        <p className="text-sm text-slate-300">{t('panels.node.assets.empty')}</p>
      ) : (
        <>
          <div className="flex gap-2 flex-wrap">
            {NODE_MODES.map((m) => (
              <button
                key={m}
                type="button"
                aria-pressed={mode === m}
                onClick={() => onModeChange(m)}
                className={`px-4 py-2 rounded-xl text-sm font-bold transition-all ${
                  mode === m ? 'bg-slate-700 text-white' : 'hover:bg-slate-800 text-slate-400'
                }`}
              >
                {t(NODE_MODE_LABEL_KEYS[m])} ({counts[m]})
              </button>
            ))}
          </div>
          <div className="overflow-auto">
            <AssetViewBody views={bodyViews} mode={bodyMode} resolve={resolve} onOpen={() => {}} />
          </div>
        </>
      )}
    </div>
  );
}

/** ノードに結びついた資産と BOM 部品の見方（AssetView と同じ集計）。 */
export function useNodeAssetViews(nodeId: string): AssetViews {
  const assets = useDiagramStore((s) => s.assets);
  const bomComponents = useDiagramStore((s) => s.bomComponents);
  const layers = useDiagramStore((s) => s.layers);
  return useMemo(() => {
    const nodes: Array<{ node: DiagramNode; layer: LayerKey }> = [];
    for (const layer of LAYER_KEYS) for (const node of layers[layer]?.nodes ?? []) nodes.push({ node, layer });
    return buildNodeAssetViews(
      nodeId,
      assets,
      nodes.map(({ node, layer }) => ({ id: node.id, type: node.type, layer })),
      listBomComponents(bomComponents, nodes),
    );
  }, [nodeId, assets, bomComponents, layers]);
}

export function NodeAssetModal({ node, onClose }: { node: DiagramNode; onClose: () => void }) {
  const t = useT();
  const findings = useDiagramStore((s) => s.findings);
  const views = useNodeAssetViews(node.id);
  const [mode, setMode] = useState<NodeAssetMode>('hosts');
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const prefix = node.seq !== undefined ? `${formatElementalId('node', node.seq)} ` : '';
  const label = `${prefix}${getNodeDisplayName(node)}`;
  const findingCount = useMemo(
    () => findings.filter((f) => f.subject?.nodeId === node.id).length,
    [findings, node.id],
  );
  const resolve = (subject: AssetSubject | undefined): ResolvedNode | null =>
    subject?.nodeId === node.id ? { label, findings: findingCount } : null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onMouseDown={onClose}
    >
      <div
        className={`${
          maximized ? 'w-[96vw] h-[94vh]' : 'w-[880px] h-[70vh]'
        } max-w-[96vw] max-h-[94vh] overflow-hidden bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 flex flex-col gap-4`}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
            <Globe size={16} className="text-sky-400" /> {t('panels.node.assets.modalTitle')}
          </span>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setMaximized((m) => !m)}
              className="text-slate-500 hover:text-slate-200 transition-colors"
              aria-label={maximized ? t('attackTree.restore') : t('attackTree.maximize')}
              title={maximized ? t('attackTree.restore') : t('attackTree.maximize')}
            >
              {maximized ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="text-slate-500 hover:text-slate-200 transition-colors"
              aria-label={t('analytics.close')}
            >
              <X size={16} />
            </button>
          </div>
        </div>
        <NodeAssetModalBody title={label} views={views} mode={mode} onModeChange={setMode} resolve={resolve} />
      </div>
    </div>
  );
}
