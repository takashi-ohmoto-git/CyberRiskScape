import { useEffect, useMemo, useState } from 'react';
import { Globe, Maximize2, Minimize2, Plus, Trash2, X } from 'lucide-react';
import { useDiagramStore } from '../../core/state/diagramStore';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import { formatElementalId } from '../../core/model/elementalId';
import type { Asset, AssetSubject, BomComponent, BomKind, DiagramNode, LayerKey } from '../../core/model/types';
import { LAYER_KEYS } from '../../core/model/types';
import { buildNodeAssetViews, type AssetViews } from '../../features/asset-view/buildAssetViews';
import {
  createManualAsset,
  isManualAsset,
  type ManualAssetError,
  type ManualAssetInput,
} from '../../features/asset-view/manualAsset';
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
  /** 手入力の資産の編集部（docs/node-address-asset-panel.md §3.2）。省略すると出さない。 */
  manual?: Omit<ManualAssetEditorProps, 'kind'>;
}

const MANUAL_ERROR_KEYS: Record<ManualAssetError, TranslationKey> = {
  hostRequired: 'panels.node.assets.manual.error.hostRequired',
  urlRequired: 'panels.node.assets.manual.error.urlRequired',
  urlInvalid: 'panels.node.assets.manual.error.urlInvalid',
  ipInvalid: 'panels.node.assets.manual.error.ipInvalid',
  portInvalid: 'panels.node.assets.manual.error.portInvalid',
  methodInvalid: 'panels.node.assets.manual.error.methodInvalid',
  duplicate: 'panels.node.assets.manual.error.duplicate',
  tooMany: 'panels.node.assets.manual.error.tooMany',
};

export interface ManualAssetEditorProps {
  /** 入力する資産の種類。タブで決まる（ホスト・ドメイン＝service、リクエスト・API＝endpoint）。 */
  kind: ManualAssetInput['kind'];
  /** このノードに手入力された資産（取り込んだ資産は含めない）。種類はこの部品の中で絞る。 */
  manualAssets: readonly Asset[];
  /** 追加に成功したら true（入力欄を空にする）。 */
  onAdd: (input: ManualAssetInput) => boolean;
  onRemove: (id: string) => void;
  /** 直近の追加の失敗理由。 */
  error?: ManualAssetError;
}

/** メソッドの選択肢（空文字＝未指定）。 */
export const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const;

const inputCls = 'w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono';

/** 手入力の資産の追加フォームと一覧（今のタブの種類だけ）。ストアには触れず props だけで動く。 */
export function ManualAssetEditor({ kind, manualAssets, onAdd, onRemove, error }: ManualAssetEditorProps) {
  const t = useT();
  const [host, setHost] = useState('');
  const [ip, setIp] = useState('');
  const [port, setPort] = useState('');
  const [url, setUrl] = useState('');
  const [method, setMethod] = useState('');
  const rows = manualAssets.filter((a) => a.kind === kind);
  const field = (id: string, label: string, value: string, set: (v: string) => void, placeholder: string) => (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-xs text-slate-400">
        {label}
      </label>
      <input
        id={id}
        type="text"
        value={value}
        placeholder={placeholder}
        onChange={(e) => set(e.target.value)}
        className={inputCls}
      />
    </div>
  );
  return (
    <section className="flex flex-col gap-3 border-t border-slate-800 pt-4">
      <h3 className="text-xs font-bold uppercase tracking-widest text-slate-300">
        {t(kind === 'service' ? 'panels.node.assets.manual.titleHost' : 'panels.node.assets.manual.titleEndpoint')}
      </h3>
      <form
        className="grid grid-cols-1 sm:grid-cols-4 gap-3 items-end"
        onSubmit={(e) => {
          e.preventDefault();
          const added = onAdd(kind === 'service' ? { kind, host, ip, port } : { kind, url, method, port });
          if (added) {
            setHost('');
            setIp('');
            setPort('');
            setUrl('');
            setMethod('');
          }
        }}
      >
        {kind === 'service' ? (
          <>
            {field('manual-asset-host', t('panels.node.assets.manual.host'), host, setHost, 'app.example.com')}
            {field('manual-asset-ip', t('panels.node.assets.manual.ip'), ip, setIp, '203.0.113.10')}
          </>
        ) : (
          <>
            {field('manual-asset-url', t('panels.node.assets.manual.url'), url, setUrl, 'https://api.example.com/v1/users')}
            <div className="flex flex-col gap-1">
              <label htmlFor="manual-asset-method" className="text-xs text-slate-400">
                {t('panels.node.assets.manual.method')}
              </label>
              <select
                id="manual-asset-method"
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                className={inputCls}
              >
                <option value="">{t('panels.node.assets.manual.methodUnset')}</option>
                {HTTP_METHODS.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>
          </>
        )}
        {field('manual-asset-port', t('panels.node.assets.manual.port'), port, setPort, '443')}
        <div>
          <button
            type="submit"
            className="flex items-center gap-1 px-3 py-2 rounded-lg text-xs font-bold bg-sky-700 hover:bg-sky-600 text-white"
          >
            <Plus size={14} /> {t('panels.node.assets.manual.add')}
          </button>
        </div>
      </form>
      {error && (
        <p role="alert" className="text-xs text-rose-400">
          {t(MANUAL_ERROR_KEYS[error])}
        </p>
      )}
      <p className="text-xs text-slate-400">{t('panels.node.assets.manual.note')}</p>
      <h4 className="text-xs font-bold text-slate-300">{t('panels.node.assets.manual.listTitle')}</h4>
      {rows.length === 0 ? (
        <p className="text-xs text-slate-400">{t('panels.node.assets.manual.listEmpty')}</p>
      ) : (
        <ul className="flex flex-col gap-1">
          {rows.map((a) => (
            <li key={a.id} className="flex items-center gap-3 text-xs text-slate-200">
              <span className="font-mono break-all flex-1">
                {a.method && <span>{a.method} </span>}
                {a.url ?? a.host}
                {a.ip && a.ip !== a.host && <span className="text-slate-400"> {a.ip}</span>}
                {a.port !== undefined && <span className="text-slate-400"> :{a.port}</span>}
              </span>
              <button
                type="button"
                onClick={() => onRemove(a.id)}
                className="flex items-center gap-1 text-slate-400 hover:text-rose-400 shrink-0"
              >
                <Trash2 size={14} /> {t('panels.node.assets.manual.remove')}
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/** タブごとの手入力の種類。部品表のタブは手入力しない。 */
const manualKindOf = (mode: NodeAssetMode): ManualAssetInput['kind'] | null =>
  mode === 'hosts' ? 'service' : mode === 'requests' || mode === 'apis' ? 'endpoint' : null;

export function NodeAssetModalBody({ title, views, mode, onModeChange, resolve, manual }: NodeAssetModalBodyProps) {
  const t = useT();
  const counts = countNodeAssetModes(views);
  const isEmpty = NODE_MODES.every((m) => counts[m] === 0);
  // 部品表のタブは、その種類の部品だけを載せた views を sbom の表で描く
  const bodyViews = isBomTab(mode) ? { ...views, sbom: bomForTab(views.sbom, mode) } : views;
  const bodyMode: AssetMode = isBomTab(mode) ? 'sbom' : mode;
  const manualKind = manualKindOf(mode);
  return (
    <div className="flex flex-col gap-4 min-h-0">
      <h2 className="text-sm font-bold text-slate-200">{title}</h2>
      {isEmpty && <p className="text-sm text-slate-300">{t('panels.node.assets.empty')}</p>}
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
      {!isEmpty && (
        <div className="overflow-auto">
          <AssetViewBody views={bodyViews} mode={bodyMode} resolve={resolve} onOpen={() => {}} />
        </div>
      )}
      {manual && manualKind && <ManualAssetEditor key={manualKind} {...manual} kind={manualKind} />}
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
  const assets = useDiagramStore((s) => s.assets);
  const setAssets = useDiagramStore((s) => s.setAssets);
  const layers = useDiagramStore((s) => s.layers);
  const activeLayer = useDiagramStore((s) => s.activeLayer);
  const [manualError, setManualError] = useState<ManualAssetError | undefined>();
  const manualAssets = useMemo(
    () => assets.filter((a) => isManualAsset(a) && a.subject?.nodeId === node.id),
    [assets, node.id],
  );
  const onAdd = (input: ManualAssetInput) => {
    const layer = LAYER_KEYS.find((l) => layers[l]?.nodes.some((n) => n.id === node.id)) ?? activeLayer;
    const r = createManualAsset(input, { layer, nodeId: node.id }, assets, new Date().toISOString());
    if (r.ok) {
      setAssets([...assets, r.asset]);
      setManualError(undefined);
      return true;
    }
    setManualError(r.error);
    return false;
  };

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
        <NodeAssetModalBody
          title={label}
          views={views}
          mode={mode}
          onModeChange={(m) => {
            setMode(m);
            setManualError(undefined);
          }}
          resolve={resolve}
          manual={{
            manualAssets,
            onAdd,
            onRemove: (id) => setAssets(assets.filter((a) => a.id !== id)),
            error: manualError,
          }}
        />
      </div>
    </div>
  );
}
