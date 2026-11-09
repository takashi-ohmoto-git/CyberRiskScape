import { useEffect, useMemo, useState } from 'react';
import { X } from 'lucide-react';
import { useDiagramStore } from '../../core/state/diagramStore';
import { getComponentRegistry } from '../../component-library/defaultRegistry';
import {
  buildDfdList,
  sortDfdFlows,
  type DfdElementRef,
  type DfdFlowSortKey,
  type SortDirection,
} from '../../features/dfd-list/buildDfdList';
import type { AuthType, EncryptionType, NetworkType, TrustLevel } from '../../core/model/types';
import { useLocale, useT, type TranslationKey } from '../../i18n';

type Tab = 'components' | 'flows';

const TRUST_KEYS: Record<TrustLevel, TranslationKey> = {
  Internal: 'panels.boundary.trust.internal',
  Partner: 'panels.boundary.trust.partner',
  Internet: 'panels.boundary.trust.internet',
};
const NETWORK_KEYS: Record<NetworkType, TranslationKey> = {
  Internet: 'panels.edge.network.internet',
  VPN: 'panels.edge.network.vpn',
  VPC: 'panels.edge.network.vpc',
};
const AUTH_KEYS: Record<AuthType, TranslationKey> = {
  None: 'panels.edge.auth.none',
  Password: 'panels.edge.auth.password',
  ApiKey: 'panels.edge.auth.apiKey',
  Token: 'panels.edge.auth.token',
  MFA: 'panels.edge.auth.mfa',
  Passkey: 'panels.edge.auth.passkey',
  Certificate: 'panels.edge.auth.certificate',
};

const TH = 'px-3 py-2 text-left text-xs font-bold text-slate-400 border-b border-slate-700 whitespace-nowrap';
const TD = 'px-3 py-2 text-xs text-slate-200 border-b border-slate-800 align-top';

/**
 * DFD LIST モーダル。アクティブレイヤーの構成要素一覧・データフロー一覧を読み取り専用で表示する。
 * 行の組み立ては features/dfd-list/buildDfdList（純関数）。
 */
export function DfdListModal() {
  const t = useT();
  const [locale] = useLocale();
  const isOpen = useDiagramStore((s) => s.isDfdListOpen);
  const close = useDiagramStore((s) => s.closeDfdList);
  const activeLayer = useDiagramStore((s) => s.activeLayer);
  const layer = useDiagramStore((s) => s.layers[s.activeLayer]);
  const [tab, setTab] = useState<Tab>('components');
  // データフローの並べ替え。null は採番順（既定）。
  const [sort, setSort] = useState<{ key: DfdFlowSortKey; dir: SortDirection } | null>(null);

  // 開くたびに構成要素タブへ戻す。
  useEffect(() => {
    if (isOpen) {
      setTab('components');
      setSort(null);
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, close]);

  const list = useMemo(() => (isOpen ? buildDfdList(layer) : { components: [], flows: [] }), [isOpen, layer]);

  if (!isOpen) return null;

  const unset = t('project.dfdList.unset');
  const ref = (r: DfdElementRef): string => `${r.displayId} ${r.name}`.trim();
  const registry = getComponentRegistry(locale);
  const encryptionLabel = (e: EncryptionType): string =>
    e === 'Plain' ? t('panels.edge.encryption.plain') : e === 'E2EE' ? t('panels.edge.encryption.e2ee') : 'TLS 1.2+';

  const flows = sort
    ? sortDfdFlows(list.flows, sort.key, sort.dir, (p) => t(`panels.edge.protocol.${p}`))
    : list.flows;
  // 同じ列をもう一度押すと向きを反転する。
  const toggleSort = (key: DfdFlowSortKey) =>
    setSort((cur) => ({ key, dir: cur?.key === key && cur.dir === 'asc' ? 'desc' : 'asc' }));
  const sortableTh = (key: DfdFlowSortKey, label: string) => {
    const dir = sort?.key === key ? sort.dir : undefined;
    return (
      <th className={TH} aria-sort={dir === 'asc' ? 'ascending' : dir === 'desc' ? 'descending' : 'none'}>
        <button
          type="button"
          onClick={() => toggleSort(key)}
          className={`flex items-center gap-1 hover:text-slate-100 ${dir ? 'text-slate-100' : ''}`}
        >
          {label}
          <span aria-hidden="true" className={dir ? 'text-blue-400' : 'text-slate-600'}>
            {dir === 'asc' ? '▲' : dir === 'desc' ? '▼' : '↕'}
          </span>
        </button>
      </th>
    );
  };

  const tabClass = (active: boolean): string =>
    `px-4 py-2 text-xs font-bold border-b-2 transition-colors ${
      active ? 'border-blue-500 text-slate-100' : 'border-transparent text-slate-500 hover:text-slate-300'
    }`;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-150"
      onMouseDown={close}
    >
      <div
        role="dialog"
        aria-modal="true"
        className="w-[1200px] max-w-[96vw] max-h-[90vh] bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-6 flex flex-col gap-4"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300">
            {t('project.dfdList.title', { layer: activeLayer })}
          </h2>
          <button
            onClick={close}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            aria-label={t('project.common.close')}
          >
            <X size={16} />
          </button>
        </div>

        <p className="text-xs text-slate-500 leading-relaxed">{t('project.dfdList.note')}</p>

        <div role="tablist" className="flex gap-1 border-b border-slate-700">
          <button
            role="tab"
            aria-selected={tab === 'components'}
            className={tabClass(tab === 'components')}
            onClick={() => setTab('components')}
          >
            {t('project.dfdList.tab.components', { count: list.components.length })}
          </button>
          <button
            role="tab"
            aria-selected={tab === 'flows'}
            className={tabClass(tab === 'flows')}
            onClick={() => setTab('flows')}
          >
            {t('project.dfdList.tab.flows', { count: list.flows.length })}
          </button>
        </div>

        <div className="overflow-auto min-h-0">
          {tab === 'components' &&
            (list.components.length === 0 ? (
              <p className="text-xs text-slate-500">{t('project.dfdList.empty.components')}</p>
            ) : (
              <table className="w-full border-collapse">
                <thead>
                  <tr>
                    <th className={TH}>{t('project.dfdList.col.id')}</th>
                    <th className={TH}>{t('project.dfdList.col.type')}</th>
                    <th className={TH}>{t('project.dfdList.col.name')}</th>
                    <th className={TH}>{t('project.dfdList.col.zone')}</th>
                    <th className={TH}>{t('project.dfdList.col.contains')}</th>
                    <th className={TH}>{t('project.dfdList.col.description')}</th>
                  </tr>
                </thead>
                <tbody>
                  {list.components.map((c) => (
                    <tr key={c.id}>
                      <td className={`${TD} font-mono whitespace-nowrap`}>{c.displayId}</td>
                      <td className={TD}>{registry.get(c.type)?.label ?? c.type}</td>
                      <td className={`${TD} font-bold`}>{c.name || unset}</td>
                      <td className={TD}>
                        {!c.parent && c.zones.length === 0 ? (
                          unset
                        ) : (
                          <ul className="flex flex-col gap-0.5">
                            {c.parent && <li>{ref(c.parent)}</li>}
                            {c.zones.map((z) => (
                              <li key={z.displayId}>
                                {ref(z)}（{t(TRUST_KEYS[z.trustLevel])}）
                              </li>
                            ))}
                          </ul>
                        )}
                      </td>
                      <td className={TD}>
                        {c.contains.length === 0 ? (
                          unset
                        ) : (
                          <ul className="flex flex-col gap-0.5">
                            {c.contains.map((x) => (
                              <li key={x.displayId}>{ref(x)}</li>
                            ))}
                          </ul>
                        )}
                      </td>
                      <td className={`${TD} whitespace-pre-wrap`}>{c.description || unset}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ))}

          {tab === 'flows' &&
            (list.flows.length === 0 ? (
              <p className="text-xs text-slate-500">{t('project.dfdList.empty.flows')}</p>
            ) : (
              <table className="w-full border-collapse">
                <thead>
                  <tr>
                    {sortableTh('id', t('project.dfdList.col.id'))}
                    {sortableTh('name', t('project.dfdList.col.flow'))}
                    {sortableTh('from', t('project.dfdList.col.from'))}
                    {sortableTh('to', t('project.dfdList.col.to'))}
                    {sortableTh('protocol', t('project.dfdList.col.protocol'))}
                    <th className={TH}>{t('project.dfdList.col.security')}</th>
                    <th className={TH}>{t('project.dfdList.col.flowDescription')}</th>
                  </tr>
                </thead>
                <tbody>
                  {flows.map((f) => (
                    <tr key={f.id}>
                      <td className={`${TD} font-mono whitespace-nowrap`}>{f.displayId}</td>
                      <td className={`${TD} font-bold`}>{f.name || unset}</td>
                      <td className={TD}>{ref(f.from)}</td>
                      <td className={TD}>
                        {/* 双方向は送信先の前に ⇄ を付けて示す */}
                        {f.bidirectional && <span aria-hidden="true">⇄ </span>}
                        {ref(f.to)}
                        {f.bidirectional && <span className="sr-only">{t('project.dfdList.bidirectional')}</span>}
                      </td>
                      <td className={TD}>
                        {f.protocol ? t(`panels.edge.protocol.${f.protocol}`) : unset}
                      </td>
                      <td className={TD}>
                        <ul className="flex flex-col gap-0.5">
                          <li>{t(NETWORK_KEYS[f.network])}</li>
                          <li>{t(AUTH_KEYS[f.auth])}</li>
                          <li>{encryptionLabel(f.encryption)}</li>
                        </ul>
                      </td>
                      <td className={`${TD} whitespace-pre-wrap`}>{f.description || unset}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ))}
        </div>
      </div>
    </div>
  );
}
