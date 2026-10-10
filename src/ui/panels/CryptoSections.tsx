import { ShieldCheck } from 'lucide-react';
import type {
  CryptoAlgorithmUpdatable,
  CryptoKeyStorage,
  CryptoManagedBy,
  CryptoTermination,
  DiagramEdge,
  DiagramNode,
  EdgeCrypto,
  NodeCrypto,
} from '../../core/model/types';
import { CRYPTO_TERMINATIONS } from '../../core/model/types';
import { useDiagramStore } from '../../core/state/diagramStore';
import { useLocale, useT } from '../../i18n';
import {
  BUNDLED_ALGORITHM_TABLE,
  getTerminationBehavior,
} from '../../crypto-behavior/bundled';
import { classifyAlgorithm } from '../../crypto-behavior/loader';
import type { AlgorithmClass } from '../../crypto-behavior/schema';

/**
 * PQC レイヤーのときだけ、ノード・エッジのパネルに出す暗号属性の入力欄。
 * 設計は docs/pqc-path-analysis.md §5。データは深度レイヤーにあっても無害だが、
 * 入力 UI は PQC レイヤーに限る。
 */

const LABEL_CLASS = 'text-xs font-black text-slate-500 uppercase block mb-1.5';
const FIELD_CLASS =
  'w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500';

/** 空の項目を落とした crypto を返す。全項目が空なら undefined（属性ごと削除）。 */
function compact<T extends object>(value: T): T | undefined {
  const entries = Object.entries(value).filter(([, v]) => v !== undefined && v !== '');
  return entries.length === 0 ? undefined : (Object.fromEntries(entries) as T);
}

const BADGE_CLASS: Record<AlgorithmClass, string> = {
  pqc: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
  transitional: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  vulnerable: 'bg-rose-500/15 text-rose-300 border-rose-500/40',
};

export function NodeCryptoSection({ node }: { node: DiagramNode }) {
  const t = useT();
  const [locale] = useLocale();
  const activeLayer = useDiagramStore((s) => s.activeLayer);
  const onUpdate = useDiagramStore((s) => s.updateNode);
  if (activeLayer !== 'PQC') return null;

  const crypto = node.crypto ?? {};
  const behavior = getTerminationBehavior(node.type, locale);
  const termLabel = (v: CryptoTermination) => t(`panels.crypto.termination.${v}`);
  // 取りうる別の構成を上位に並べ、残りの値を続ける。
  const alternatives = behavior?.alternatives ?? [];
  const termOptions = [
    ...alternatives,
    ...CRYPTO_TERMINATIONS.filter((v) => !alternatives.includes(v)),
  ];
  const defaultLabel = t('panels.crypto.terminationDefault', {
    label: behavior ? termLabel(behavior.default) : t('panels.crypto.terminationEndpoint'),
  });
  const set = (patch: Partial<NodeCrypto>) => onUpdate(node.id, 'crypto', compact({ ...crypto, ...patch }));
  const id = (name: string) => `node-crypto-${name}-${node.id}`;

  return (
    <div
      className="bg-slate-800/50 p-4 rounded-2xl border border-slate-700"
      data-testid="node-crypto-section"
    >
      <h3 className="text-xs font-bold text-slate-300 mb-4 flex items-center gap-2">
        <ShieldCheck size={14} className="text-blue-500" /> {t('panels.crypto.nodeSection')}
      </h3>
      <div className="space-y-3">
        <div>
          <label htmlFor={id('termination')} className={LABEL_CLASS}>
            {t('panels.crypto.termination')}
          </label>
          <select
            id={id('termination')}
            value={crypto.termination ?? ''}
            onChange={(e) =>
              set({ termination: e.target.value === '' ? undefined : (e.target.value as CryptoTermination) })
            }
            className={FIELD_CLASS}
          >
            <option value="">{defaultLabel}</option>
            {termOptions.map((v) => (
              <option key={v} value={v}>
                {termLabel(v)}
              </option>
            ))}
          </select>
          {behavior && (
            <p className="text-xs text-slate-500 mt-2 leading-relaxed">{behavior.note}</p>
          )}
        </div>
        <div>
          <label htmlFor={id('managedBy')} className={LABEL_CLASS}>
            {t('panels.crypto.managedBy')}
          </label>
          <select
            id={id('managedBy')}
            value={crypto.managedBy ?? ''}
            onChange={(e) =>
              set({ managedBy: e.target.value === '' ? undefined : (e.target.value as CryptoManagedBy) })
            }
            className={FIELD_CLASS}
          >
            <option value="">{t('panels.crypto.unset')}</option>
            <option value="self">{t('panels.crypto.managedBy.self')}</option>
            <option value="provider">{t('panels.crypto.managedBy.provider')}</option>
          </select>
        </div>
        <div>
          <label htmlFor={id('signature')} className={LABEL_CLASS}>
            {t('panels.crypto.signature')}
          </label>
          <input
            id={id('signature')}
            type="text"
            maxLength={200}
            value={crypto.signature ?? ''}
            onChange={(e) => set({ signature: e.target.value })}
            placeholder={t('panels.crypto.signaturePlaceholder')}
            className={FIELD_CLASS}
          />
        </div>
        <div>
          <label htmlFor={id('keyStorage')} className={LABEL_CLASS}>
            {t('panels.crypto.keyStorage')}
          </label>
          <select
            id={id('keyStorage')}
            value={crypto.keyStorage ?? ''}
            onChange={(e) =>
              set({ keyStorage: e.target.value === '' ? undefined : (e.target.value as CryptoKeyStorage) })
            }
            className={FIELD_CLASS}
          >
            <option value="">{t('panels.crypto.unset')}</option>
            {(['hsm', 'kms', 'software', 'unknown'] as const).map((v) => (
              <option key={v} value={v}>
                {t(`panels.crypto.keyStorage.${v}`)}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor={id('algorithmUpdatable')} className={LABEL_CLASS}>
            {t('panels.crypto.algorithmUpdatable')}
          </label>
          <select
            id={id('algorithmUpdatable')}
            value={crypto.algorithmUpdatable ?? ''}
            onChange={(e) =>
              set({
                algorithmUpdatable:
                  e.target.value === '' ? undefined : (e.target.value as CryptoAlgorithmUpdatable),
              })
            }
            className={FIELD_CLASS}
          >
            <option value="">{t('panels.crypto.unset')}</option>
            {(['yes', 'no', 'unknown'] as const).map((v) => (
              <option key={v} value={v}>
                {t(`panels.crypto.algorithmUpdatable.${v}`)}
              </option>
            ))}
          </select>
        </div>
      </div>
    </div>
  );
}

export function EdgeCryptoSection({ edge }: { edge: DiagramEdge }) {
  const t = useT();
  const activeLayer = useDiagramStore((s) => s.activeLayer);
  const onUpdate = useDiagramStore((s) => s.updateEdge);
  if (activeLayer !== 'PQC') return null;

  const crypto = edge.crypto ?? {};
  const set = (patch: Partial<EdgeCrypto>) => onUpdate(edge.id, 'crypto', compact({ ...crypto, ...patch }));
  const id = (name: string) => `edge-crypto-${name}-${edge.id}`;

  const textField = (
    key: keyof EdgeCrypto,
    label: string,
    placeholder: string,
    withBadge: boolean,
  ) => {
    const value = crypto[key] ?? '';
    const cls = withBadge ? classifyAlgorithm(value, BUNDLED_ALGORITHM_TABLE) : null;
    return (
      <div>
        <label htmlFor={id(key)} className={LABEL_CLASS}>
          {label}
        </label>
        <div className="flex items-center gap-2">
          <input
            id={id(key)}
            type="text"
            maxLength={200}
            value={value}
            onChange={(e) => set({ [key]: e.target.value })}
            placeholder={placeholder}
            className={FIELD_CLASS}
          />
          {cls && (
            <span
              data-testid={`edge-crypto-badge-${key}`}
              className={`shrink-0 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-bold ${BADGE_CLASS[cls]}`}
            >
              {t(`panels.crypto.class.${cls}`)}
            </span>
          )}
        </div>
      </div>
    );
  };

  return (
    <section data-testid="edge-crypto-section">
      <h3 className="text-xs font-black text-slate-500 uppercase mb-3 flex items-center gap-2">
        <ShieldCheck size={14} className="text-blue-500" /> {t('panels.crypto.edgeSection')}
      </h3>
      <div className="space-y-3">
        {textField('protocol', t('panels.crypto.protocol'), t('panels.crypto.protocolPlaceholder'), false)}
        {textField('version', t('panels.crypto.version'), t('panels.crypto.versionPlaceholder'), false)}
        {textField('kex', t('panels.crypto.kex'), t('panels.crypto.kexPlaceholder'), true)}
        {textField(
          'signature',
          t('panels.crypto.edgeSignature'),
          t('panels.crypto.edgeSignaturePlaceholder'),
          true,
        )}
      </div>
    </section>
  );
}
