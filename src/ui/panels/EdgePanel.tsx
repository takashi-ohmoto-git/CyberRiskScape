import type { ReactNode } from 'react';
import {
  ArrowLeftRight,
  ArrowRight,
  ArrowLeft,
  Link as LinkIcon,
  Lock,
  ShieldCheck,
  Unlock,
} from 'lucide-react';
import type {
  AuthType,
  ComponentTypeId,
  DataFlow,
  DiagramEdge,
  EdgeSemantic,
  EncryptionType,
  NetworkType,
} from '../../core/model/types';
import { selectActiveNodes, useDiagramStore } from '../../core/state/diagramStore';
import { useT } from '../../i18n';

type TFunc = ReturnType<typeof useT>;

interface EdgePanelProps {
  edge: DiagramEdge;
}

interface OptionDef<T extends string> {
  val: T;
  label: string;
  icon?: ReactNode;
}

function getAuthOptions(t: TFunc): OptionDef<AuthType>[] {
  return [
    { val: 'None', label: t('panels.edge.auth.none'), icon: <Unlock size={14} /> },
    { val: 'Password', label: t('panels.edge.auth.password'), icon: <Lock size={14} /> },
    { val: 'MFA', label: t('panels.edge.auth.mfa'), icon: <ShieldCheck size={14} /> },
  ];
}

function getNetworkOptions(t: TFunc): OptionDef<NetworkType>[] {
  return [
    { val: 'Internet', label: t('panels.edge.network.internet') },
    { val: 'VPN', label: t('panels.edge.network.vpn') },
    { val: 'VPC', label: t('panels.edge.network.vpc') },
  ];
}

function getEncryptionOptions(t: TFunc): OptionDef<EncryptionType>[] {
  return [
    { val: 'Plain', label: t('panels.edge.encryption.plain') },
    { val: 'TLS', label: 'TLS 1.2+' },
    { val: 'E2EE', label: t('panels.edge.encryption.e2ee') },
  ];
}

function getDataFlowOptions(t: TFunc): OptionDef<DataFlow>[] {
  return [
    { val: 'outbound', label: t('panels.edge.dataFlow.outbound'), icon: <ArrowRight size={14} /> },
    { val: 'inbound', label: t('panels.edge.dataFlow.inbound'), icon: <ArrowLeft size={14} /> },
    { val: 'bidirectional', label: t('panels.edge.dataFlow.bidirectional'), icon: <ArrowLeftRight size={14} /> },
  ];
}

/**
 * エッジ意味論（[[plan]] §2.22 1.6d）の選択肢。
 * 値の意味は src/core/model/types.ts の EdgeSemantic を参照。
 */
function getSemanticOptions(t: TFunc): { val: EdgeSemantic; label: string }[] {
  return [
    { val: 'data_flow', label: t('panels.edge.semantic.dataFlow') },
    { val: 'tool_invocation', label: t('panels.edge.semantic.toolInvocation') },
    { val: 'delegation', label: t('panels.edge.semantic.delegation') },
    { val: 'memory_read', label: t('panels.edge.semantic.memoryRead') },
    { val: 'memory_write', label: t('panels.edge.semantic.memoryWrite') },
    { val: 'rag_retrieval', label: t('panels.edge.semantic.ragRetrieval') },
  ];
}

/**
 * source / target 型から推奨される semantic 値を返す。
 * 該当しない場合は undefined。表示用ヒントのみで、自動入力はしない（B 原則）。
 */
function recommendSemantic(
  sourceType: ComponentTypeId | undefined,
  targetType: ComponentTypeId | undefined,
): EdgeSemantic | undefined {
  if (!sourceType || !targetType) return undefined;
  if (sourceType === 'AGENT' && targetType === 'TOOL') return 'tool_invocation';
  if (sourceType === 'AGENT' && targetType === 'AGENT') return 'delegation';
  if (sourceType === 'AGENT' && targetType === 'DB') return 'rag_retrieval';
  return undefined;
}

export function EdgePanel({ edge }: EdgePanelProps) {
  const t = useT();
  const AUTH_OPTIONS = getAuthOptions(t);
  const NETWORK_OPTIONS = getNetworkOptions(t);
  const ENCRYPTION_OPTIONS = getEncryptionOptions(t);
  const DATA_FLOW_OPTIONS = getDataFlowOptions(t);
  const SEMANTIC_OPTIONS = getSemanticOptions(t);
  const onUpdate = useDiagramStore((s) => s.updateEdge);
  const deleteEdge = useDiagramStore((s) => s.deleteEdge);
  const onClose = useDiagramStore((s) => s.clearSelection);
  const allNodes = useDiagramStore(selectActiveNodes);
  const sourceType = allNodes.find((n) => n.id === edge.source)?.type;
  const targetType = allNodes.find((n) => n.id === edge.target)?.type;
  const recommended = recommendSemantic(sourceType, targetType);
  const onDelete = (id: string) => {
    deleteEdge(id);
    onClose();
  };
  return (
    <div className="flex flex-col h-full">
      <div className="p-6 border-b border-slate-800 bg-blue-600/5">
        <div className="flex items-center gap-2 mb-2">
          <LinkIcon size={20} className="text-blue-500" />
          <h2 className="text-lg font-black tracking-tight">Edge Properties</h2>
        </div>
      </div>
      <div className="p-6 space-y-8 flex-1">
        <section>
          <label className="text-[10px] font-black text-slate-500 uppercase mb-3 block">
            Data Flow
          </label>
          <div className="grid grid-cols-1 gap-2">
            {DATA_FLOW_OPTIONS.map((opt) => {
              const current = edge.dataFlow ?? 'outbound';
              return (
                <button
                  key={opt.val}
                  onClick={() => onUpdate(edge.id, 'dataFlow', opt.val)}
                  className={`flex items-center gap-3 p-3 rounded-xl border transition-all text-xs font-bold ${
                    current === opt.val
                      ? 'bg-blue-600 border-blue-400 text-white'
                      : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                  }`}
                >
                  {opt.icon} {opt.label}
                </button>
              );
            })}
          </div>
          <div className="mt-3">
            <label className="text-[10px] font-black text-slate-500 uppercase mb-2 block">
              Data Flow Name
            </label>
            <input
              type="text"
              value={edge.dataFlowName ?? ''}
              onChange={(e) => {
                const v = e.target.value;
                // 空文字は未設定として扱う（schema が min(1) のため）
                onUpdate(edge.id, 'dataFlowName', v.length > 0 ? v : undefined);
              }}
              maxLength={80}
              placeholder={t('panels.edge.dataFlowNamePlaceholder')}
              className="w-full bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-xs font-bold text-white placeholder-slate-500 focus:outline-none focus:border-blue-400"
            />
          </div>
        </section>
        <section>
          <label
            htmlFor={`edge-semantic-${edge.id}`}
            className="text-[10px] font-black text-slate-500 uppercase mb-2 block"
          >
            {t('panels.edge.semanticLabel')}
          </label>
          <select
            id={`edge-semantic-${edge.id}`}
            value={edge.semantic ?? ''}
            onChange={(e) =>
              onUpdate(
                edge.id,
                'semantic',
                e.target.value === '' ? undefined : (e.target.value as EdgeSemantic),
              )
            }
            className="w-full bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-xs font-bold text-white focus:outline-none focus:border-blue-400"
          >
            <option value="">{t('panels.edge.semanticUnset')}</option>
            {SEMANTIC_OPTIONS.map((opt) => (
              <option key={opt.val} value={opt.val}>
                {opt.label}
              </option>
            ))}
          </select>
          {recommended && edge.semantic === undefined && (
            <p className="text-[9px] text-blue-400 mt-2 leading-relaxed">
              {t('panels.edge.recommendedPrefix')}
              <code className="font-mono bg-slate-900/60 px-1.5 py-0.5 rounded">{recommended}</code>
              {t('panels.edge.recommendedSuffix', { sourceType: sourceType ?? '', targetType: targetType ?? '' })}
            </p>
          )}
        </section>
        <section>
          <label className="text-[10px] font-black text-slate-500 uppercase mb-3 block">
            Authentication
          </label>
          <div className="grid grid-cols-1 gap-2">
            {AUTH_OPTIONS.map((opt) => (
              <button
                key={opt.val}
                onClick={() => onUpdate(edge.id, 'auth', opt.val)}
                className={`flex items-center gap-3 p-3 rounded-xl border transition-all text-xs font-bold ${
                  edge.auth === opt.val
                    ? 'bg-blue-600 border-blue-400 text-white'
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                }`}
              >
                {opt.icon} {opt.label}
              </button>
            ))}
          </div>
        </section>
        <section>
          <label className="text-[10px] font-black text-slate-500 uppercase mb-3 block">
            Network Path
          </label>
          <div className="grid grid-cols-1 gap-2">
            {NETWORK_OPTIONS.map((opt) => (
              <button
                key={opt.val}
                onClick={() => onUpdate(edge.id, 'network', opt.val)}
                className={`p-3 rounded-xl border text-xs font-bold transition-all ${
                  edge.network === opt.val
                    ? 'bg-blue-600 border-blue-400 text-white'
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </section>
        <section>
          <label className="text-[10px] font-black text-slate-500 uppercase mb-3 block">
            Encryption
          </label>
          <div className="grid grid-cols-1 gap-2">
            {ENCRYPTION_OPTIONS.map((opt) => (
              <button
                key={opt.val}
                onClick={() => onUpdate(edge.id, 'encryption', opt.val)}
                className={`p-3 rounded-xl border text-xs font-bold transition-all ${
                  edge.encryption === opt.val
                    ? 'bg-blue-600 border-blue-400 text-white'
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </section>
        <button
          onClick={() => onDelete(edge.id)}
          className="w-full py-3 rounded-xl bg-rose-600/10 text-rose-500 border border-rose-600/30 text-xs font-black hover:bg-rose-600/20"
        >
          DELETE EDGE
        </button>
      </div>
      <div className="p-6 border-t border-slate-800">
        <button onClick={onClose} className="w-full bg-slate-800 py-3 rounded-xl font-bold text-xs">
          {t('panels.common.close')}
        </button>
      </div>
    </div>
  );
}
