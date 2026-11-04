import { useMemo, useState } from 'react';
import { selectPrimaryNodeId, useDiagramStore } from '../../core/state/diagramStore';
import { getNodeDisplayName } from '../../core/model/nodeDisplay';
import { formatElementalId } from '../../core/model/elementalId';
import type { Asset, AssetSubject, BomComponent, BomKind, DiagramNode, LayerKey } from '../../core/model/types';
import { LAYER_KEYS } from '../../core/model/types';
import {
  buildAssetViews,
  type ApiGroup,
  type AssetViews,
  type HostRow,
} from '../../features/asset-view/buildAssetViews';
import { listBomComponents } from '../../features/bom-import/listBomComponents';
import { useT, type TranslationKey } from '../../i18n';

/**
 * Asset タブの画面（docs/architecture.md §8.7）。読み取り専用。
 * 表の部分は props だけで描ける AssetViewBody に分け、テストしやすくしている。
 */

export type AssetMode = 'hosts' | 'requests' | 'apis' | 'sbom';

/** 結びついたノードの表示用情報。解決できなければ null（未対応）。 */
export interface ResolvedNode {
  label: string;
  findings: number;
  /** 右パネルに表示中のノードか。 */
  selected?: boolean;
}

export interface AssetViewBodyProps {
  views: AssetViews;
  mode: AssetMode;
  resolve: (subject: AssetSubject | undefined) => ResolvedNode | null;
  onOpen: (subject: AssetSubject) => void;
}

const TH = 'px-3 py-2 text-left text-xs font-bold text-slate-400 border-b border-slate-700 whitespace-nowrap';
const TD = 'px-3 py-2 align-top border-b border-slate-800 text-sm text-slate-200';
const CHIP = 'inline-block px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-xs text-slate-300';

function Chips({ items, mono }: { items: string[]; mono?: boolean }) {
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((x) => (
        <span key={x} className={`${CHIP} ${mono ? 'font-mono' : ''}`}>
          {x}
        </span>
      ))}
    </div>
  );
}

function NodeCell({ resolved }: { resolved: ResolvedNode | null }) {
  const t = useT();
  if (!resolved) {
    return (
      <span className="text-amber-400 font-bold" title={t('project.assetView.unmapped')}>
        {t('project.assetView.unmapped')}
      </span>
    );
  }
  return <span>{resolved.label}</span>;
}

/** 行のクリック・キーボード操作。対応ノードが無い行は何もしない。 */
function rowProps(subject: AssetSubject | undefined, resolved: ResolvedNode | null, onOpen: AssetViewBodyProps['onOpen']) {
  if (!subject || !resolved) return { className: 'opacity-90' };
  return {
    className: `cursor-pointer hover:bg-slate-900 focus:outline-none focus:ring-1 focus:ring-slate-500 ${resolved.selected ? 'bg-blue-950' : ''}`,
    'aria-selected': !!resolved.selected,
    tabIndex: 0,
    onClick: () => onOpen(subject),
    onKeyDown: (e: React.KeyboardEvent) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        onOpen(subject);
      }
    },
  };
}

function HostsTable({ rows, resolve, onOpen }: { rows: HostRow[]; resolve: AssetViewBodyProps['resolve']; onOpen: AssetViewBodyProps['onOpen'] }) {
  const t = useT();
  return (
    <table className="w-full border-collapse">
      <thead>
        <tr>
          <th className={TH}>{t('project.assetView.col.host')}</th>
          <th className={TH}>{t('project.assetView.col.domain')}</th>
          <th className={TH}>{t('project.assetView.col.ports')}</th>
          <th className={TH} title={t('project.assetView.col.technologiesHint')}>
            {t('project.assetView.col.technologies')}
          </th>
          <th className={TH}>{t('project.assetView.col.node')}</th>
          <th className={TH}>{t('project.assetView.col.findings')}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => {
          const subject = r.subjects[0];
          const resolved = r.subjects.map((s) => resolve(s)).find((x) => x !== null) ?? null;
          return (
            <tr key={r.host} {...rowProps(r.subjects.find((s) => resolve(s)) ?? subject, resolved, onOpen)}>
              <td className={`${TD} font-mono`}>{r.host}</td>
              <td className={TD}>{r.domains.join(', ')}</td>
              <td className={TD}>
                <Chips items={r.ports} mono />
              </td>
              <td className={TD}>
                <Chips items={r.technologies} />
              </td>
              <td className={TD}>
                <NodeCell resolved={resolved} />
              </td>
              <td className={`${TD} tabular-nums`}>{resolved ? resolved.findings : ''}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

const KIND_LABEL_KEYS: Record<BomKind, TranslationKey> = {
  software: 'project.assetView.kind.software',
  crypto: 'project.assetView.kind.crypto',
  'ai-model': 'project.assetView.kind.ai-model',
  dataset: 'project.assetView.kind.dataset',
  other: 'project.assetView.kind.other',
};

function SbomTable({ rows, resolve, onOpen }: { rows: BomComponent[]; resolve: AssetViewBodyProps['resolve']; onOpen: AssetViewBodyProps['onOpen'] }) {
  const t = useT();
  return (
    <table className="w-full border-collapse">
      <thead>
        <tr>
          <th className={TH}>{t('project.assetView.col.name')}</th>
          <th className={TH}>{t('project.assetView.col.version')}</th>
          <th className={TH}>{t('project.assetView.col.kind')}</th>
          <th className={TH}>{t('project.assetView.col.identifier')}</th>
          <th className={TH}>{t('project.assetView.col.source')}</th>
          <th className={TH}>{t('project.assetView.col.node')}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((c) => {
          const resolved = resolve(c.subject);
          const id = c.identifiers.find((i) => i.scheme === 'purl') ?? c.identifiers.find((i) => i.scheme === 'cpe');
          return (
            <tr key={c.id} {...rowProps(c.subject, resolved, onOpen)}>
              <td className={TD}>{c.name}</td>
              <td className={`${TD} font-mono`}>{c.version ?? ''}</td>
              <td className={TD}>{t(KIND_LABEL_KEYS[c.kind])}</td>
              <td className={`${TD} font-mono break-all`}>{id?.value ?? ''}</td>
              <td className={TD}>{c.source.product}</td>
              <td className={TD}>
                <NodeCell resolved={resolved} />
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function methodClass(method: string | undefined): string {
  if (method === 'POST') return 'bg-orange-900/50 text-orange-300 border-orange-700';
  if (method === 'GET') return 'bg-sky-900/50 text-sky-300 border-sky-700';
  return 'bg-slate-800 text-slate-300 border-slate-700';
}

function EndpointsTable({ endpoints, resolve, onOpen }: { endpoints: Asset[]; resolve: AssetViewBodyProps['resolve']; onOpen: AssetViewBodyProps['onOpen'] }) {
  const t = useT();
  return (
    <table className="w-full border-collapse">
      <thead>
        <tr>
          <th className={TH}>{t('project.assetView.col.method')}</th>
          <th className={TH}>{t('project.assetView.col.url')}</th>
          <th className={TH}>{t('project.assetView.col.params')}</th>
          <th className={TH}>{t('project.assetView.col.node')}</th>
        </tr>
      </thead>
      <tbody>
        {endpoints.map((e) => {
          const resolved = resolve(e.subject);
          return (
            <tr key={e.id} {...rowProps(e.subject, resolved, onOpen)}>
              <td className={TD}>
                <span className={`inline-block px-2 py-0.5 rounded border text-xs font-bold ${methodClass(e.method)}`}>
                  {e.method ?? '-'}
                </span>
              </td>
              <td className={`${TD} font-mono break-all`}>{e.url ?? e.host}</td>
              <td className={TD}>
                <Chips items={(e.params ?? []).map((p) => `${p.name}(${p.location})`)} mono />
              </td>
              <td className={TD}>
                <NodeCell resolved={resolved} />
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

export function AssetViewBody({ views, mode, resolve, onOpen }: AssetViewBodyProps) {
  const t = useT();
  const empty = <p className="text-sm text-slate-400 p-4">{t('project.assetView.emptyMode')}</p>;
  if (mode === 'hosts') {
    return views.hosts.length === 0 ? empty : <HostsTable rows={views.hosts} resolve={resolve} onOpen={onOpen} />;
  }
  if (mode === 'sbom') {
    return views.sbom.length === 0 ? empty : <SbomTable rows={views.sbom} resolve={resolve} onOpen={onOpen} />;
  }
  if (mode === 'requests') {
    return views.requests.length === 0 ? empty : <EndpointsTable endpoints={views.requests} resolve={resolve} onOpen={onOpen} />;
  }
  if (views.apis.length === 0) return empty;
  return (
    <div className="space-y-6">
      {views.apis.map((g: ApiGroup, i) => {
        const resolved = resolve(g.subject);
        const title = resolved ? resolved.label : g.product;
        return (
          <section key={`${g.subject?.nodeId ?? g.product}-${i}`}>
            <h3 className="text-sm font-bold text-slate-200 mb-2">
              {title}
              <span className="ml-2 text-xs font-normal text-slate-400">
                {g.fromDefinition
                  ? t('project.assetView.apiFromDefinition', { product: g.product })
                  : g.product}
              </span>
            </h3>
            <EndpointsTable endpoints={g.endpoints} resolve={resolve} onOpen={onOpen} />
          </section>
        );
      })}
    </div>
  );
}

const MODES: AssetMode[] = ['hosts', 'requests', 'apis', 'sbom'];
const MODE_LABEL_KEYS = {
  hosts: 'project.assetView.mode.hosts',
  requests: 'project.assetView.mode.requests',
  apis: 'project.assetView.mode.apis',
  sbom: 'project.assetView.mode.sbom',
} as const;

export function AssetView() {
  const t = useT();
  const isOpen = useDiagramStore((s) => s.isAssetViewOpen);
  const assets = useDiagramStore((s) => s.assets);
  const bomComponents = useDiagramStore((s) => s.bomComponents);
  const layers = useDiagramStore((s) => s.layers);
  const findings = useDiagramStore((s) => s.findings);
  const setActiveLayer = useDiagramStore((s) => s.setActiveLayer);
  const selectNode = useDiagramStore((s) => s.selectNode);
  const selectedNodeId = useDiagramStore(selectPrimaryNodeId);
  const [mode, setMode] = useState<AssetMode>('hosts');

  const nodes = useMemo(() => {
    const list: Array<{ node: DiagramNode; layer: LayerKey }> = [];
    for (const layer of LAYER_KEYS) for (const node of layers[layer]?.nodes ?? []) list.push({ node, layer });
    return list;
  }, [layers]);

  const views = useMemo(
    () =>
      buildAssetViews(
        assets,
        nodes.map(({ node, layer }) => ({ id: node.id, type: node.type, layer })),
        listBomComponents(bomComponents, nodes),
      ),
    [assets, bomComponents, nodes],
  );

  const resolve = useMemo(() => {
    const byKey = new Map(nodes.map(({ node, layer }) => [`${layer}:${node.id}`, node]));
    const counts = new Map<string, number>();
    for (const f of findings) {
      const id = f.subject?.nodeId;
      if (id) counts.set(id, (counts.get(id) ?? 0) + 1);
    }
    return (subject: AssetSubject | undefined): ResolvedNode | null => {
      const node = subject && byKey.get(`${subject.layer}:${subject.nodeId}`);
      if (!node) return null;
      const prefix = node.seq !== undefined ? `${formatElementalId('node', node.seq)} ` : '';
      return { label: `${prefix}${getNodeDisplayName(node)}`, findings: counts.get(node.id) ?? 0, selected: node.id === selectedNodeId };
    };
  }, [nodes, findings, selectedNodeId]);

  if (!isOpen) return null;

  const onOpen = (subject: AssetSubject) => {
    // 同じ行をもう一度押すと選択を解き、右パネルは全体の脅威一覧に戻る
    if (subject.nodeId === selectedNodeId) {
      selectNode(null);
      return;
    }
    setActiveLayer(subject.layer);
    selectNode(subject.nodeId);
  };

  const apiCount = views.apis.reduce((n, g) => n + g.endpoints.length, 0);
  const counts: Record<AssetMode, number> = {
    hosts: views.hosts.length,
    requests: views.requests.length,
    apis: apiCount,
    sbom: views.sbom.length,
  };

  return (
    <div className="absolute inset-0 z-[5] bg-slate-950 pt-36 px-6 pb-6 overflow-auto select-text">
      {assets.length === 0 && views.sbom.length === 0 ? (
        <p className="text-sm text-slate-300 max-w-2xl">{t('project.assetView.emptyAll')}</p>
      ) : (
        <>
          <p className="text-xs text-slate-400 mb-3">{t('project.assetView.privacyNote')}</p>
          <div className="flex gap-2 mb-4">
            {MODES.map((m) => (
              <button
                key={m}
                aria-pressed={mode === m}
                onClick={() => setMode(m)}
                className={`px-4 py-2 rounded-xl text-sm font-bold transition-all ${
                  mode === m ? 'bg-slate-700 text-white' : 'hover:bg-slate-800 text-slate-400'
                }`}
              >
                {t(MODE_LABEL_KEYS[m])} ({counts[m]})
              </button>
            ))}
          </div>
          <AssetViewBody views={views} mode={mode} resolve={resolve} onOpen={onOpen} />
        </>
      )}
    </div>
  );
}
