import { useState } from 'react';
import {
  Bot,
  Briefcase,
  Building2,
  ChevronDown,
  ChevronRight,
  Cloud,
  Crosshair,
  GitBranch,
  Link as LinkIcon,
  Package,
  PackageOpen,
  Plus,
  Radar,
  ShieldCheck,
  ShieldOff,
  Skull,
  Tag,
  User,
  UserCheck,
  UserCog,
  UserX,
} from 'lucide-react';
import type {
  AgencyLevel,
  AgentAttributes,
  AttackSurfaceAttribute,
  AttackSurfaceKey,
  BlastRadius,
  CloudOwnership,
  CloudSanctionStatus,
  ComponentTypeId,
  DiagramNode,
  IdentityTier,
  ManagedState,
  ThreatActorType,
  ThreatView,
  UserTrustAttribute,
} from '../../core/model/types';
import {
  AGENCY_APPLICABLE,
  ATTACK_OBJECTIVE_APPLICABLE,
  IDENTITY_TIER_APPLICABLE,
  isSuppressed,
  SANCTION_ATTRIBUTE_APPLICABLE,
  THREAT_ACTOR_TYPE_APPLICABLE,
} from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { componentRegistry } from '../../component-library/defaultRegistry';
import { renderIcon } from '../../component-library/iconRegistry';
import { selectActiveNodes, useDiagramStore } from '../../core/state/diagramStore';
import { ThreatCard } from './ThreatCard';
import { AttackTreeModal } from './AttackTreeModal';

/** 管理状態（Managed/Unmanaged）を持つコンポーネント型。 */
const MANAGED_STATE_APPLICABLE: ReadonlySet<ComponentTypeId> = new Set([
  'PC',
  'SMARTPHONE',
  'IOT',
]);

const MANAGED_OPTIONS: { val: ManagedState; label: string; icon: typeof ShieldCheck; color: string }[] = [
  { val: 'Managed', label: 'Managed (管理下)', icon: ShieldCheck, color: 'text-emerald-400' },
  { val: 'Unmanaged', label: 'Unmanaged (未管理)', icon: ShieldOff, color: 'text-rose-400' },
];

/** USER ノードに Trust Attribute（信頼区分）UI を表示する。 */
const USER_TRUST_APPLICABLE: ReadonlySet<ComponentTypeId> = new Set(['USER']);

/**
 * USER の Trust Attribute → managedState の派生マップ。
 * Guest は Untrusted 相当 (Unmanaged)、他は組織統制下 (Managed) を既定とする。
 */
const USER_TRUST_TO_MANAGED: Record<UserTrustAttribute, ManagedState> = {
  Guest: 'Unmanaged',
  Employee: 'Managed',
  Contractor: 'Managed',
  Partner: 'Managed',
};

const USER_TRUST_OPTIONS: {
  val: UserTrustAttribute;
  label: string;
  icon: typeof UserCheck;
  color: string;
}[] = [
  { val: 'Guest', label: 'Guest (来訪者)', icon: UserX, color: 'text-rose-400' },
  { val: 'Employee', label: '正社員', icon: UserCheck, color: 'text-emerald-400' },
  { val: 'Contractor', label: '契約社員', icon: UserCog, color: 'text-amber-400' },
  { val: 'Partner', label: '取引先', icon: Briefcase, color: 'text-indigo-400' },
];

/** 認可状況・所有状況属性の選択肢。適用対象は SANCTION_ATTRIBUTE_APPLICABLE（Cloud / App 型）。 */
const CLOUD_SANCTION_OPTIONS: {
  val: CloudSanctionStatus;
  label: string;
  icon: typeof ShieldCheck;
  color: string;
}[] = [
  { val: 'Sanctioned', label: 'Sanctioned (認可済み)', icon: ShieldCheck, color: 'text-emerald-400' },
  { val: 'Unsanctioned', label: 'Unsanctioned (未認可)', icon: ShieldOff, color: 'text-rose-400' },
];

const CLOUD_OWNERSHIP_OPTIONS: {
  val: CloudOwnership;
  label: string;
  icon: typeof Building2;
  color: string;
}[] = [
  { val: 'Company', label: '自社', icon: Building2, color: 'text-emerald-400' },
  { val: 'ThirdParty', label: '他社', icon: Briefcase, color: 'text-amber-400' },
  { val: 'Personal', label: '個人', icon: User, color: 'text-rose-400' },
];

/** 攻撃者区分（THREAT_ACTOR の Type 属性）の選択肢。 */
const THREAT_ACTOR_TYPE_OPTIONS: { val: ThreatActorType; label: string }[] = [
  { val: 'CyberCriminals', label: 'Cyber Criminals — サイバー犯罪者' },
  { val: 'NationStateActors', label: 'Nation-State Actors — 国家支援型' },
  { val: 'FinanciallyMotivatedActors', label: 'Financially motivated actors — 金銭目的' },
  { val: 'Hacktivists', label: 'Hacktivists — 思想・主張目的' },
  { val: 'ScriptKiddies', label: 'Script Kiddies — 低スキル・既製ツール' },
];

/**
 * Attack Surface Attribute を表示するコンポーネント型。
 * Web/外部公開ポイント（FRONT_END_SERVER / GATEWAY）のみ対象。
 */
const ATTACK_SURFACE_APPLICABLE: ReadonlySet<ComponentTypeId> = new Set([
  'FRONT_END_SERVER',
  'GATEWAY',
]);

/**
 * 未設定ノード用のデフォルト値（insecure baseline）。
 * 脅威エンジン側 `resolveAttackSurface` と必ず一致させること。
 */
const ATTACK_SURFACE_DEFAULTS: Required<AttackSurfaceAttribute> = {
  hasGlobalIp: true,
  hasSourceIpRestriction: false,
  hasRemoteAccessRestriction: false,
  hasUserAuthentication: false,
  hasAccessLog: false,
  hasWafProtection: false,
  hasDdosProtection: false,
};

const ATTACK_SURFACE_FIELDS: { key: AttackSurfaceKey; label: string }[] = [
  { key: 'hasGlobalIp', label: 'Global IP の割り当て' },
  { key: 'hasSourceIpRestriction', label: '送信元 IP アクセス制限' },
  { key: 'hasRemoteAccessRestriction', label: 'リモートアクセス制限' },
  { key: 'hasUserAuthentication', label: 'ユーザー認証' },
  { key: 'hasAccessLog', label: 'アクセスログ' },
  { key: 'hasWafProtection', label: 'WAF / WAP による保護' },
  { key: 'hasDdosProtection', label: 'DoS / DDoS 保護' },
];

/**
 * エージェント特有属性（[[plan]] §2.22 1.6b）の選択肢。
 * 値の意味は src/core/model/types.ts を参照。
 */
const AGENCY_OPTIONS: { val: AgencyLevel; label: string }[] = [
  { val: 'None', label: 'None — エージェント性なし' },
  { val: 'Advisory', label: 'Advisory — 提案のみ' },
  { val: 'Bounded', label: 'Bounded — 許可リスト内 + HITL' },
  { val: 'Autonomous', label: 'Autonomous — 複数ツール自律' },
];

const BLAST_RADIUS_OPTIONS: { val: BlastRadius; label: string }[] = [
  { val: 'ReadOnly', label: 'ReadOnly — 読取専用' },
  { val: 'Self', label: 'Self — 自ノードに閉じる' },
  { val: 'Tenant', label: 'Tenant — 同一テナント内' },
  { val: 'CrossTenant', label: 'CrossTenant — 顧客境界越え' },
  { val: 'Admin', label: 'Admin — 管理者 / インフラ全体' },
];

const IDENTITY_TIER_OPTIONS: { val: IdentityTier; label: string }[] = [
  { val: 'LabelOnly', label: 'LabelOnly — 文字列 ID のみ' },
  { val: 'Cryptographic', label: 'Cryptographic — X.509 等' },
  { val: 'HardwareBound', label: 'HardwareBound — HSM / TPM' },
];

interface NodePanelProps {
  node: DiagramNode;
  threats: ThreatView[];
  /** アクティブレイヤーの全 ThreatView（Attack Tree の経路重み付けに使う）。 */
  allThreats: ThreatView[];
}

export function NodePanel({ node, threats, allThreats }: NodePanelProps) {
  const onUpdate = useDiagramStore((s) => s.updateNode);
  const onStartLinking = useDiagramStore((s) => s.setLinkingFromId);
  const onClose = useDiagramStore((s) => s.clearSelection);
  const setNodeParent = useDiagramStore((s) => s.setNodeParent);
  const setNodePosition = useDiagramStore((s) => s.setNodePosition);
  const selectNode = useDiagramStore((s) => s.selectNode);
  const allNodes = useDiagramStore(selectActiveNodes);
  const config = componentRegistry.get(node.type);
  const typeLabel = config?.label ?? node.type;
  const colorClass = config?.color ?? 'bg-slate-500';
  const showManagedState = MANAGED_STATE_APPLICABLE.has(node.type);
  const showUserTrust = USER_TRUST_APPLICABLE.has(node.type);
  const showAttackSurface = ATTACK_SURFACE_APPLICABLE.has(node.type);
  const showCloudAttrs = SANCTION_ATTRIBUTE_APPLICABLE.has(node.type);
  const showAttacker = ATTACK_OBJECTIVE_APPLICABLE.has(node.type);
  const showThreatActorType = THREAT_ACTOR_TYPE_APPLICABLE.has(node.type);
  // objective の候補：同一レイヤー上の自分以外の非攻撃者ノード。
  const objectiveCandidates = allNodes.filter(
    (n) => n.id !== node.id && !ATTACK_OBJECTIVE_APPLICABLE.has(n.type),
  );
  // 標的が削除済み等で候補に無い場合は「未設定」表示にフォールバック。
  const objectiveValue = objectiveCandidates.some((n) => n.id === node.attackObjectiveId)
    ? (node.attackObjectiveId as string)
    : '';
  const showAgency = AGENCY_APPLICABLE.has(node.type);
  const showIdentityTier = IDENTITY_TIER_APPLICABLE.has(node.type);
  // blastRadius は全ノード型で有意味なので、エージェント属性セクション自体は常に表示。
  // agency / identityTier は適用対象ノード型のみ表示する。
  const [agentAttrsOpen, setAgentAttrsOpen] = useState(false);
  const [attackTreeOpen, setAttackTreeOpen] = useState(false);

  /** エージェント属性 1 フィールドだけを更新（他フィールドは保持）。空文字選択で undefined に戻す。 */
  const onUpdateAgentAttr = <K extends keyof AgentAttributes>(
    key: K,
    value: AgentAttributes[K] | undefined,
  ) => {
    const current: AgentAttributes = { ...node.agentAttributes };
    if (value === undefined) {
      delete current[key];
    } else {
      current[key] = value;
    }
    // 全フィールド空なら attribute 自体を未設定に。
    const hasAny =
      current.agency !== undefined ||
      current.blastRadius !== undefined ||
      current.identityTier !== undefined;
    onUpdate(node.id, 'agentAttributes', hasAny ? current : undefined);
  };

  const onSelectUserTrust = (val: UserTrustAttribute) => {
    onUpdate(node.id, 'userTrustAttribute', val);
    onUpdate(node.id, 'managedState', USER_TRUST_TO_MANAGED[val]);
  };

  const onToggleAttackSurface = (key: AttackSurfaceKey, value: boolean) => {
    const current: AttackSurfaceAttribute = { ...ATTACK_SURFACE_DEFAULTS, ...node.attackSurface };
    onUpdate(node.id, 'attackSurface', { ...current, [key]: value });
  };

  const resolvedSurface: Required<AttackSurfaceAttribute> = {
    ...ATTACK_SURFACE_DEFAULTS,
    ...node.attackSurface,
  };

  const parentNode = node.parentId
    ? (allNodes.find((n) => n.id === node.parentId) ?? null)
    : null;
  const childNodes = allNodes.filter((n) => n.parentId === node.id);

  const handleDetach = () => {
    if (!parentNode) {
      setNodeParent(node.id, undefined);
      return;
    }
    // 親解除時は親のすぐ下に配置して、隠れたまま画面外に置き去りにならないようにする。
    setNodePosition(node.id, parentNode.x + 24, parentNode.y + 120);
    setNodeParent(node.id, undefined);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="p-6 border-b border-slate-800 bg-blue-600/5">
        <div className="flex items-center gap-3 mb-2">
          <div className={`${colorClass} p-2 rounded-lg text-white`}>
            {renderIcon(config?.icon ?? { kind: 'builtin', name: 'box' }, { size: 20 })}
          </div>
          <h2 className="text-lg font-black tracking-tight">{typeLabel}</h2>
        </div>
        <p className="text-[10px] text-slate-500 font-bold uppercase">ID: {node.id}</p>
      </div>

      <div className="p-6 flex-1 space-y-6 overflow-y-auto">
        <div className="bg-slate-800/50 p-4 rounded-2xl border border-slate-700 space-y-4">
          <h3 className="text-xs font-bold text-slate-300 flex items-center gap-2">
            <Tag size={14} className="text-blue-500" /> プロパティ
          </h3>
          <div>
            <label
              htmlFor={`node-label-${node.id}`}
              className="text-[10px] font-black text-slate-500 uppercase block mb-1.5"
            >
              表示名
            </label>
            <input
              id={`node-label-${node.id}`}
              type="text"
              value={node.label ?? ''}
              onChange={(e) => onUpdate(node.id, 'label', e.target.value)}
              placeholder={typeLabel}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-bold text-slate-100 focus:outline-none focus:border-blue-500 placeholder:text-slate-600 placeholder:font-normal"
            />
            <p className="text-[9px] text-slate-500 mt-1.5 leading-relaxed">
              例: "与信判定サービス" / "顧客マスターDB"
            </p>
          </div>
          <div>
            <label
              htmlFor={`node-desc-${node.id}`}
              className="text-[10px] font-black text-slate-500 uppercase block mb-1.5"
            >
              説明
            </label>
            <textarea
              id={`node-desc-${node.id}`}
              value={node.description ?? ''}
              onChange={(e) => onUpdate(node.id, 'description', e.target.value)}
              placeholder="このコンポーネントの責務・業務ルール・取扱データ等..."
              rows={4}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500 placeholder:text-slate-600 resize-y"
            />
          </div>
        </div>

        {parentNode && (
          <div className="bg-slate-800/50 p-4 rounded-2xl border border-slate-700">
            <h3 className="text-xs font-bold text-slate-300 mb-3 flex items-center gap-2">
              <Package size={14} className="text-amber-500" /> 内包元
            </h3>
            <div className="flex items-center justify-between gap-2">
              <button
                onClick={() => selectNode(parentNode.id)}
                className="flex items-center gap-2 flex-1 min-w-0 bg-slate-900 hover:bg-slate-800 px-3 py-2 rounded-lg border border-slate-700 text-left transition-colors"
                title="親ノードを選択"
              >
                <div
                  className={`${componentRegistry.get(parentNode.type)?.color ?? 'bg-slate-500'} p-1 rounded text-white shrink-0`}
                >
                  {renderIcon(
                    componentRegistry.get(parentNode.type)?.icon ?? { kind: 'builtin', name: 'box' },
                    { size: 10 },
                  )}
                </div>
                <span className="text-[11px] font-bold text-slate-200 truncate">
                  {parentNode.label || componentRegistry.get(parentNode.type)?.label || parentNode.type}
                </span>
              </button>
              <button
                onClick={handleDetach}
                className="shrink-0 px-3 py-2 bg-amber-600/20 hover:bg-amber-600/30 border border-amber-600/40 text-amber-300 rounded-lg text-[10px] font-black uppercase transition-colors flex items-center gap-1"
                title="親から外してトップレベルに戻す"
              >
                <PackageOpen size={12} /> 外す
              </button>
            </div>
          </div>
        )}

        {childNodes.length > 0 && (
          <div className="bg-slate-800/50 p-4 rounded-2xl border border-slate-700">
            <h3 className="text-xs font-bold text-slate-300 mb-3 flex items-center gap-2">
              <Package size={14} className="text-blue-500" /> 内包コンポーネント ({childNodes.length})
            </h3>
            <div className="space-y-1.5">
              {childNodes.map((child) => {
                const childConfig = componentRegistry.get(child.type);
                return (
                  <button
                    key={child.id}
                    onClick={() => selectNode(child.id)}
                    className="w-full flex items-center gap-2 bg-slate-900 hover:bg-slate-800 px-3 py-2 rounded-lg border border-slate-700 text-left transition-colors"
                  >
                    <div
                      className={`${childConfig?.color ?? 'bg-slate-500'} p-1 rounded text-white shrink-0`}
                    >
                      {renderIcon(childConfig?.icon ?? { kind: 'builtin', name: 'box' }, { size: 10 })}
                    </div>
                    <span className="text-[11px] font-bold text-slate-200 truncate flex-1">
                      {child.label || childConfig?.label || child.type}
                    </span>
                    <span className="text-[9px] text-slate-500 shrink-0">
                      {childConfig?.label ?? child.type}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {showUserTrust && (
          <div className="bg-slate-800/50 p-4 rounded-2xl border border-slate-700">
            <h3 className="text-xs font-bold text-slate-300 mb-4 flex items-center gap-2">
              <ShieldCheck size={14} className="text-blue-500" /> Trust Attribute
            </h3>
            <div className="grid grid-cols-1 gap-2">
              {USER_TRUST_OPTIONS.map((opt) => {
                const Icon = opt.icon;
                const selected = node.userTrustAttribute === opt.val;
                return (
                  <button
                    key={opt.val}
                    onClick={() => onSelectUserTrust(opt.val)}
                    className={`flex items-center gap-3 p-3 rounded-xl border transition-all text-xs font-bold ${
                      selected
                        ? 'bg-blue-600 border-blue-400 text-white'
                        : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                    }`}
                  >
                    <span className={selected ? 'text-white' : opt.color}>
                      <Icon size={14} />
                    </span>
                    {opt.label}
                  </button>
                );
              })}
            </div>
            <p className="text-[9px] text-slate-500 mt-3 leading-relaxed">
              ユーザーの信頼区分。Guest は未管理（Untrusted）、その他は組織統制下として
              管理状態が自動設定される。
            </p>
          </div>
        )}

        {showManagedState && (
          <div className="bg-slate-800/50 p-4 rounded-2xl border border-slate-700">
            <h3 className="text-xs font-bold text-slate-300 mb-4 flex items-center gap-2">
              <ShieldCheck size={14} className="text-blue-500" /> Trust Attribute
            </h3>
            <div className="grid grid-cols-1 gap-2">
              {MANAGED_OPTIONS.map((opt) => {
                const Icon = opt.icon;
                const selected = node.managedState === opt.val;
                return (
                  <button
                    key={opt.val}
                    onClick={() => onUpdate(node.id, 'managedState', opt.val)}
                    className={`flex items-center gap-3 p-3 rounded-xl border transition-all text-xs font-bold ${
                      selected
                        ? 'bg-blue-600 border-blue-400 text-white'
                        : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                    }`}
                  >
                    <span className={selected ? 'text-white' : opt.color}>
                      <Icon size={14} />
                    </span>
                    {opt.label}
                  </button>
                );
              })}
            </div>
            <p className="text-[9px] text-slate-500 mt-3 leading-relaxed">
              MDM・EDR 等の組織統制下にあるかどうか。未管理端末は攻撃面が大きい。
            </p>
          </div>
        )}

        {showCloudAttrs && (
          <div className="bg-slate-800/50 p-4 rounded-2xl border border-slate-700">
            <h3 className="text-xs font-bold text-slate-300 mb-4 flex items-center gap-2">
              <Cloud size={14} className="text-blue-500" /> Sanction / Ownership Attribute
            </h3>
            <p className="text-[10px] font-black text-slate-500 uppercase mb-2">認可状況</p>
            <div className="grid grid-cols-1 gap-2 mb-4">
              {CLOUD_SANCTION_OPTIONS.map((opt) => {
                const Icon = opt.icon;
                const selected = node.cloudSanction === opt.val;
                return (
                  <button
                    key={opt.val}
                    onClick={() => onUpdate(node.id, 'cloudSanction', opt.val)}
                    className={`flex items-center gap-3 p-3 rounded-xl border transition-all text-xs font-bold ${
                      selected
                        ? 'bg-blue-600 border-blue-400 text-white'
                        : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                    }`}
                  >
                    <span className={selected ? 'text-white' : opt.color}>
                      <Icon size={14} />
                    </span>
                    {opt.label}
                  </button>
                );
              })}
            </div>
            <p className="text-[10px] font-black text-slate-500 uppercase mb-2">所有状況</p>
            <div className="grid grid-cols-1 gap-2">
              {CLOUD_OWNERSHIP_OPTIONS.map((opt) => {
                const Icon = opt.icon;
                const selected = node.cloudOwnership === opt.val;
                return (
                  <button
                    key={opt.val}
                    onClick={() => onUpdate(node.id, 'cloudOwnership', opt.val)}
                    className={`flex items-center gap-3 p-3 rounded-xl border transition-all text-xs font-bold ${
                      selected
                        ? 'bg-blue-600 border-blue-400 text-white'
                        : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                    }`}
                  >
                    <span className={selected ? 'text-white' : opt.color}>
                      <Icon size={14} />
                    </span>
                    {opt.label}
                  </button>
                );
              })}
            </div>
            <p className="text-[9px] text-slate-500 mt-3 leading-relaxed">
              クラウドサービス / 業務アプリの認可状況（組織が認可・統制しているか）と
              所有状況（自社契約 / 他社所有 / 個人アカウント）。未設定は「不明」扱い。
            </p>
          </div>
        )}

        {showAttacker && (
          <div className="bg-slate-800/50 p-4 rounded-2xl border border-slate-700">
            <h3 className="text-xs font-bold text-slate-300 mb-4 flex items-center gap-2">
              <Skull size={14} className="text-blue-500" /> Attacker Attribute
            </h3>
            <div className="space-y-3">
              {showThreatActorType && (
                <div>
                  <label
                    htmlFor={`node-actortype-${node.id}`}
                    className="text-[10px] font-black text-slate-500 uppercase block mb-1.5"
                  >
                    Type（攻撃者区分）
                  </label>
                  <select
                    id={`node-actortype-${node.id}`}
                    value={node.threatActorType ?? ''}
                    onChange={(e) =>
                      onUpdate(
                        node.id,
                        'threatActorType',
                        e.target.value === '' ? undefined : (e.target.value as ThreatActorType),
                      )
                    }
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                  >
                    <option value="">— 未設定 —</option>
                    {THREAT_ACTOR_TYPE_OPTIONS.map((opt) => (
                      <option key={opt.val} value={opt.val}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                </div>
              )}
              <div>
                <label
                  htmlFor={`node-objective-${node.id}`}
                  className="text-[10px] font-black text-slate-500 uppercase mb-1.5 flex items-center gap-1.5"
                >
                  <Crosshair size={12} className="text-rose-400" /> Objective（標的コンポーネント）
                </label>
                <select
                  id={`node-objective-${node.id}`}
                  value={objectiveValue}
                  onChange={(e) =>
                    onUpdate(
                      node.id,
                      'attackObjectiveId',
                      e.target.value === '' ? undefined : e.target.value,
                    )
                  }
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                >
                  <option value="">— 未設定 —</option>
                  {objectiveCandidates.map((n) => {
                    const cfg = componentRegistry.get(n.type);
                    const name = n.label || cfg?.label || n.type;
                    const prefix = n.seq !== undefined ? `${formatElementalId('node', n.seq)}: ` : '';
                    return (
                      <option key={n.id} value={n.id}>
                        {prefix}
                        {name}
                      </option>
                    );
                  })}
                </select>
              </div>
              <button
                onClick={() => setAttackTreeOpen(true)}
                disabled={objectiveValue === ''}
                className="w-full bg-rose-600 hover:bg-rose-500 disabled:bg-slate-800 disabled:text-slate-600 disabled:cursor-not-allowed py-3 rounded-xl font-black text-xs transition-all flex items-center justify-center gap-2 shadow-lg shadow-rose-900/20"
                title={
                  objectiveValue === ''
                    ? 'Objective（標的）を設定すると攻撃経路分析を表示できます'
                    : '攻撃者から標的までの攻撃経路分析を表示'
                }
              >
                <GitBranch size={16} /> 攻撃経路分析
              </button>
            </div>
            <p className="text-[9px] text-slate-500 mt-3 leading-relaxed">
              攻撃者の区分と objective（標的とするコンポーネント）。標的に指定したノードが
              削除されると objective は自動解除される。攻撃経路分析はエッジを辿って
              攻撃者から標的までの到達経路を表示する。
            </p>
          </div>
        )}

        {showAttackSurface && (
          <div className="bg-slate-800/50 p-4 rounded-2xl border border-slate-700">
            <h3 className="text-xs font-bold text-slate-300 mb-4 flex items-center gap-2">
              <Radar size={14} className="text-blue-500" /> Attack Surface Attribute
            </h3>
            <div className="space-y-2">
              {ATTACK_SURFACE_FIELDS.map(({ key, label }) => {
                const value = resolvedSurface[key];
                return (
                  <div
                    key={key}
                    className="flex items-center justify-between gap-3 bg-slate-900/60 rounded-xl border border-slate-700 px-3 py-2"
                  >
                    <span className="text-[11px] font-bold text-slate-300 leading-tight">{label}</span>
                    <div className="flex items-center gap-1 shrink-0">
                      <button
                        onClick={() => onToggleAttackSurface(key, true)}
                        className={`px-2.5 py-1 rounded-lg text-[10px] font-black transition-all ${
                          value
                            ? 'bg-emerald-600 text-white border border-emerald-400'
                            : 'bg-slate-800 text-slate-500 border border-slate-700 hover:border-slate-500'
                        }`}
                      >
                        有り
                      </button>
                      <button
                        onClick={() => onToggleAttackSurface(key, false)}
                        className={`px-2.5 py-1 rounded-lg text-[10px] font-black transition-all ${
                          !value
                            ? 'bg-rose-600 text-white border border-rose-400'
                            : 'bg-slate-800 text-slate-500 border border-slate-700 hover:border-slate-500'
                        }`}
                      >
                        無し
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
            <p className="text-[9px] text-slate-500 mt-3 leading-relaxed">
              Web サーバー等の公開ポイントの攻撃面構成。未設定時は Global IP=有り、その他=無し
              の insecure baseline として脅威評価される。
            </p>
          </div>
        )}

        <div className="bg-slate-800/50 rounded-2xl border border-slate-700">
          <button
            onClick={() => setAgentAttrsOpen((v) => !v)}
            className="w-full px-4 py-3 flex items-center justify-between text-xs font-bold text-slate-300 hover:text-slate-100 transition-colors"
            aria-expanded={agentAttrsOpen}
          >
            <span className="flex items-center gap-2">
              <Bot size={14} className="text-blue-500" /> エージェント属性
              {node.agentAttributes && (
                <span className="text-[9px] font-black px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300">
                  設定済み
                </span>
              )}
            </span>
            {agentAttrsOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </button>
          {agentAttrsOpen && (
            <div className="px-4 pb-4 space-y-3 border-t border-slate-700/60 pt-4">
              {showAgency && (
                <div>
                  <label
                    htmlFor={`node-agency-${node.id}`}
                    className="text-[10px] font-black text-slate-500 uppercase block mb-1.5"
                  >
                    Agency（自律度）
                  </label>
                  <select
                    id={`node-agency-${node.id}`}
                    value={node.agentAttributes?.agency ?? ''}
                    onChange={(e) =>
                      onUpdateAgentAttr(
                        'agency',
                        e.target.value === '' ? undefined : (e.target.value as AgencyLevel),
                      )
                    }
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                  >
                    <option value="">— 未設定 —</option>
                    {AGENCY_OPTIONS.map((opt) => (
                      <option key={opt.val} value={opt.val}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                </div>
              )}
              <div>
                <label
                  htmlFor={`node-blastradius-${node.id}`}
                  className="text-[10px] font-black text-slate-500 uppercase block mb-1.5"
                >
                  Blast Radius（侵害時の影響範囲）
                </label>
                <select
                  id={`node-blastradius-${node.id}`}
                  value={node.agentAttributes?.blastRadius ?? ''}
                  onChange={(e) =>
                    onUpdateAgentAttr(
                      'blastRadius',
                      e.target.value === '' ? undefined : (e.target.value as BlastRadius),
                    )
                  }
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                >
                  <option value="">— 未設定 —</option>
                  {BLAST_RADIUS_OPTIONS.map((opt) => (
                    <option key={opt.val} value={opt.val}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
              {showIdentityTier && (
                <div>
                  <label
                    htmlFor={`node-identitytier-${node.id}`}
                    className="text-[10px] font-black text-slate-500 uppercase block mb-1.5"
                  >
                    Identity Tier（アイデンティティの根付き方）
                  </label>
                  <select
                    id={`node-identitytier-${node.id}`}
                    value={node.agentAttributes?.identityTier ?? ''}
                    onChange={(e) =>
                      onUpdateAgentAttr(
                        'identityTier',
                        e.target.value === '' ? undefined : (e.target.value as IdentityTier),
                      )
                    }
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                  >
                    <option value="">— 未設定 —</option>
                    {IDENTITY_TIER_OPTIONS.map((opt) => (
                      <option key={opt.val} value={opt.val}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                </div>
              )}
              <p className="text-[9px] text-slate-500 leading-relaxed">
                Anthropic "Zero Trust for AI Agents" 由来の設計者宣言属性。未設定属性は将来の脅威エンジンで「最悪を仮定」評価される予定（[[plan]] §2.22 1.6c）。
              </p>
            </div>
          )}
        </div>

        <div className="bg-slate-800/50 p-4 rounded-2xl border border-slate-700">
          <h3 className="text-xs font-bold text-slate-300 mb-4 flex items-center gap-2">
            <LinkIcon size={14} className="text-blue-500" /> エッジの作成
          </h3>
          <button
            onClick={() => onStartLinking(node.id)}
            className="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded-xl font-black text-xs transition-all flex items-center justify-center gap-2 shadow-lg shadow-blue-900/20"
          >
            <Plus size={16} /> CREATE LINK
          </button>
          <p className="text-[9px] text-slate-500 mt-3 leading-relaxed">
            このパーツから別のパーツへの接続線を作成します。
          </p>
        </div>

        {threats.length > 0 && (
          <div>
            <h3 className="text-xs font-bold text-rose-500 mb-3 uppercase tracking-widest">
              Active Threats ({threats.filter((t) => !isSuppressed(t)).length})
            </h3>
            <div className="space-y-3">
              {threats.map((t) => (
                <ThreatCard key={t.id} threat={t} />
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="p-6 border-t border-slate-800">
        <button onClick={onClose} className="w-full bg-slate-800 py-3 rounded-xl font-bold text-xs">
          閉じる
        </button>
      </div>

      {attackTreeOpen && showAttacker && (
        <AttackTreeModal
          attacker={node}
          allThreats={allThreats}
          onClose={() => setAttackTreeOpen(false)}
        />
      )}
    </div>
  );
}
