import { useEffect, useState, type ReactNode } from 'react';
import {
  Box,
  Building,
  ChevronDown,
  ChevronsDown,
  ChevronsUp,
  ChevronUp,
  Database,
  Eye,
  EyeOff,
  Globe,
  Layers,
  Lock,
  Network,
  ShieldAlert,
  ShieldCheck,
  Users,
} from 'lucide-react';
import type {
  DiagramBoundary,
  MacroTrustAttribute,
  MicroSegmentationStatus,
  MicroTrustAttribute,
  SensitiveData,
  TrustLevel,
} from '../../core/model/types';
import { useDiagramStore, type ReorderAction } from '../../core/state/diagramStore';
import {
  BOUNDARY_TYPES,
  MACRO_TRUST_TO_TRUST_LEVEL,
  MICRO_TRUST_TO_TRUST_LEVEL,
} from '../../core/constants/boundaryTypes';

interface BoundaryPanelProps {
  boundary: DiagramBoundary;
}

interface ReorderOption {
  action: ReorderAction;
  label: string;
  icon: ReactNode;
}

const REORDER_OPTIONS: ReorderOption[] = [
  { action: 'front', label: '最前面へ移動', icon: <ChevronsUp size={14} /> },
  { action: 'forward', label: '前面へ移動', icon: <ChevronUp size={14} /> },
  { action: 'backward', label: '背面へ移動', icon: <ChevronDown size={14} /> },
  { action: 'back', label: '最背面へ移動', icon: <ChevronsDown size={14} /> },
];

interface TrustOption {
  val: TrustLevel;
  label: string;
  icon: ReactNode;
  color: string;
}

const TRUST_OPTIONS: TrustOption[] = [
  { val: 'Internal', label: '社内 (Internal)', icon: <Building size={14} />, color: 'text-emerald-400' },
  { val: 'Partner', label: '取引先 (Partner)', icon: <Users size={14} />, color: 'text-orange-400' },
  { val: 'Internet', label: 'インターネット (Internet)', icon: <Globe size={14} />, color: 'text-blue-400' },
];

interface MacroTrustOption {
  val: MacroTrustAttribute;
  label: string;
  icon: ReactNode;
  color: string;
}

const MACRO_TRUST_OPTIONS: MacroTrustOption[] = [
  { val: 'Public Area', label: 'Public Area', icon: <Globe size={14} />, color: 'text-blue-400' },
  { val: 'Office Area', label: 'Office Area', icon: <Building size={14} />, color: 'text-emerald-400' },
  { val: 'Security Zone', label: 'Security Zone', icon: <Lock size={14} />, color: 'text-purple-400' },
];

interface MicroTrustOption {
  val: MicroTrustAttribute;
  label: string;
  color: string;
}

const MICRO_TRUST_OPTIONS: MicroTrustOption[] = [
  { val: 'Development', label: 'Development', color: 'text-amber-400' },
  { val: 'Staging', label: 'Staging', color: 'text-cyan-400' },
  { val: 'Production', label: 'Production', color: 'text-emerald-400' },
];

interface MicroStatusOption {
  val: MicroSegmentationStatus;
  label: string;
  icon: ReactNode;
  color: string;
}

const MICRO_STATUS_OPTIONS: MicroStatusOption[] = [
  { val: '適用済み', label: '適用済み', icon: <ShieldCheck size={14} />, color: 'text-emerald-400' },
  { val: '未適用', label: '未適用', icon: <ShieldAlert size={14} />, color: 'text-rose-400' },
];

interface SensitiveDataOption {
  val: SensitiveData;
  label: string;
  icon: ReactNode;
  color: string;
}

const SENSITIVE_DATA_OPTIONS: SensitiveDataOption[] = [
  { val: '無し', label: '無し', icon: <EyeOff size={14} />, color: 'text-slate-400' },
  { val: '個人情報', label: '個人情報', icon: <Eye size={14} />, color: 'text-amber-400' },
  { val: '機密情報', label: '機密情報', icon: <Lock size={14} />, color: 'text-rose-400' },
];

/** IPv4 CIDR の簡易検証（例: 10.0.0.0/24）。空文字は valid 扱い（未入力）。 */
const CIDR_RE =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/(3[0-2]|[12]?\d)$/;

function isValidCidr(input: string): boolean {
  if (input.trim() === '') return true;
  return CIDR_RE.test(input.trim());
}

export function BoundaryPanel({ boundary }: BoundaryPanelProps) {
  const onUpdate = useDiagramStore((s) => s.updateBoundary);
  const onReorder = useDiagramStore((s) => s.reorderBoundary);
  const onClose = useDiagramStore((s) => s.clearSelection);
  const typeName = BOUNDARY_TYPES[boundary.type].name;

  const onSelectMacro = (val: MacroTrustAttribute) => {
    onUpdate(boundary.id, 'macroTrust', val);
    onUpdate(boundary.id, 'trustLevel', MACRO_TRUST_TO_TRUST_LEVEL[val]);
  };
  const onSelectMicro = (val: MicroTrustAttribute) => {
    onUpdate(boundary.id, 'microTrust', val);
    onUpdate(boundary.id, 'trustLevel', MICRO_TRUST_TO_TRUST_LEVEL[val]);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="p-6 border-b border-slate-800 bg-emerald-600/5">
        <div className="flex items-center gap-2 mb-2">
          <Box size={20} className="text-emerald-500" />
          <h2 className="text-lg font-black tracking-tight">Boundary Properties</h2>
        </div>
        <p className="text-[10px] text-slate-500 font-bold uppercase">{typeName}</p>
      </div>
      <div className="p-6 space-y-8 flex-1 overflow-y-auto">
        {boundary.type === 'RECT' && (
          <TrustLevelSection
            value={boundary.trustLevel}
            onChange={(val) => onUpdate(boundary.id, 'trustLevel', val)}
          />
        )}

        {boundary.type === 'RECT_DASHED' && (
          <DmzSection
            boundary={boundary}
            onUpdateField={onUpdate}
          />
        )}

        {boundary.type === 'ROUNDED' && (
          <MacroSection
            boundary={boundary}
            onSelectMacro={onSelectMacro}
            onUpdateField={onUpdate}
          />
        )}

        {boundary.type === 'ROUNDED_DASHED' && (
          <MicroSection
            boundary={boundary}
            onSelectMicro={onSelectMicro}
            onUpdateField={onUpdate}
          />
        )}

        <section>
          <label className="text-[10px] font-black text-slate-500 uppercase flex items-center gap-2 mb-3">
            <Layers size={12} className="text-emerald-500" /> Arrange (重なり順)
          </label>
          <div className="grid grid-cols-2 gap-2">
            {REORDER_OPTIONS.map((opt) => (
              <button
                key={opt.action}
                onClick={() => onReorder(boundary.id, opt.action)}
                className="flex items-center gap-2 p-2.5 rounded-xl border bg-slate-800 border-slate-700 text-slate-300 hover:border-emerald-500 hover:text-emerald-400 transition-all text-[11px] font-bold"
              >
                <span className="text-slate-400">{opt.icon}</span>
                {opt.label}
              </button>
            ))}
          </div>
        </section>
        <section>
          <label className="text-[10px] font-black text-slate-500 uppercase block mb-3">
            Dimensions
          </label>
          <p className="text-[10px] text-slate-500 leading-relaxed">
            キャンバス上で境界を選択し、四隅または辺中央のハンドル
            <span className="inline-block w-2 h-2 bg-white border border-blue-500 mx-1 align-middle" />
            をドラッグしてサイズを変更できます。現在のサイズ:{' '}
            <span className="text-slate-300 font-bold">
              {Math.round(boundary.width)} × {Math.round(boundary.height)}
            </span>
          </p>
        </section>
      </div>
      <div className="p-6 border-t border-slate-800">
        <button onClick={onClose} className="w-full bg-slate-800 py-3 rounded-xl font-bold text-xs">
          閉じる
        </button>
      </div>
    </div>
  );
}

function TrustLevelSection({
  value,
  onChange,
}: {
  value: TrustLevel;
  onChange: (val: TrustLevel) => void;
}) {
  return (
    <section>
      <label className="text-[10px] font-black text-slate-500 uppercase flex items-center gap-2 mb-3">
        Trust Attribute
      </label>
      <div className="grid grid-cols-1 gap-2">
        {TRUST_OPTIONS.map((opt) => (
          <button
            key={opt.val}
            onClick={() => onChange(opt.val)}
            className={`flex items-center gap-3 p-3 rounded-xl border transition-all text-xs font-bold ${
              value === opt.val
                ? 'bg-emerald-600 border-emerald-400 text-white'
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
            }`}
          >
            <span className={value === opt.val ? 'text-white' : opt.color}>{opt.icon}</span>{' '}
            {opt.label}
          </button>
        ))}
      </div>
    </section>
  );
}

function DmzSection({
  boundary,
  onUpdateField,
}: {
  boundary: DiagramBoundary;
  onUpdateField: <K extends keyof DiagramBoundary>(
    id: string,
    field: K,
    value: DiagramBoundary[K],
  ) => void;
}) {
  // DMZ は trustLevel='Internet' 固定。旧データで他値が入っていれば即時補正する。
  useEffect(() => {
    if (boundary.trustLevel !== 'Internet') {
      onUpdateField(boundary.id, 'trustLevel', 'Internet');
    }
  }, [boundary.id, boundary.trustLevel, onUpdateField]);

  return (
    <section>
      <label className="text-[10px] font-black text-slate-500 uppercase flex items-center gap-2 mb-3">
        Trust Attribute
      </label>
      <div className="flex items-center gap-3 p-3 rounded-xl border bg-emerald-600 border-emerald-400 text-white text-xs font-bold">
        <Globe size={14} />
        DMZ
        <span className="ml-auto text-[10px] font-bold text-emerald-100/80">
          ≡ Internet
        </span>
      </div>
      <p className="text-[10px] text-slate-500 mt-2 leading-relaxed">
        DMZ 境界は Internet 相当の信頼レベルとして脅威判定に使われます。
      </p>
    </section>
  );
}

function MacroSection({
  boundary,
  onSelectMacro,
  onUpdateField,
}: {
  boundary: DiagramBoundary;
  onSelectMacro: (val: MacroTrustAttribute) => void;
  onUpdateField: <K extends keyof DiagramBoundary>(
    id: string,
    field: K,
    value: DiagramBoundary[K],
  ) => void;
}) {
  return (
    <>
      <section>
        <label className="text-[10px] font-black text-slate-500 uppercase flex items-center gap-2 mb-3">
          Trust Attribute
        </label>
        <div className="grid grid-cols-1 gap-2">
          {MACRO_TRUST_OPTIONS.map((opt) => (
            <button
              key={opt.val}
              onClick={() => onSelectMacro(opt.val)}
              className={`flex items-center gap-3 p-3 rounded-xl border transition-all text-xs font-bold ${
                boundary.macroTrust === opt.val
                  ? 'bg-emerald-600 border-emerald-400 text-white'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              <span className={boundary.macroTrust === opt.val ? 'text-white' : opt.color}>
                {opt.icon}
              </span>{' '}
              {opt.label}
            </button>
          ))}
        </div>
      </section>
      <section>
        <label className="text-[10px] font-black text-slate-500 uppercase flex items-center gap-2 mb-3">
          <Network size={12} className="text-emerald-500" /> Network Attribute
        </label>
        <div className="space-y-3">
          <div>
            <label className="text-[10px] text-slate-400 font-bold block mb-1">VLAN Name</label>
            <input
              type="text"
              value={boundary.vlanName ?? ''}
              onChange={(e) =>
                onUpdateField(boundary.id, 'vlanName', e.target.value || undefined)
              }
              placeholder="例: vlan-office-01"
              maxLength={64}
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-emerald-500"
            />
          </div>
          <VlanIdInput
            value={boundary.vlanId}
            onChange={(v) => onUpdateField(boundary.id, 'vlanId', v)}
          />
          <NetworkAddressInput
            value={boundary.networkAddress ?? ''}
            onChange={(v) => onUpdateField(boundary.id, 'networkAddress', v || undefined)}
          />
        </div>
      </section>
    </>
  );
}

function VlanIdInput({
  value,
  onChange,
}: {
  value: number | undefined;
  onChange: (val: number | undefined) => void;
}) {
  // 入力中の文字列を保持し、空欄や入力途中の状態も維持する。
  const [draft, setDraft] = useState(value === undefined ? '' : String(value));
  useEffect(() => {
    setDraft(value === undefined ? '' : String(value));
  }, [value]);
  const trimmed = draft.trim();
  const parsed = trimmed === '' ? undefined : Number(trimmed);
  const valid =
    parsed === undefined ||
    (Number.isInteger(parsed) && parsed >= 0 && parsed <= 4094);
  return (
    <div>
      <label className="text-[10px] text-slate-400 font-bold block mb-1">VLAN ID</label>
      <input
        type="number"
        inputMode="numeric"
        min={0}
        max={4094}
        step={1}
        value={draft}
        onChange={(e) => {
          // 数字以外を弾く（type=number でも一部ブラウザは "e" 等を許容する）。
          const next = e.target.value.replace(/[^0-9]/g, '');
          setDraft(next);
          if (next === '') {
            onChange(undefined);
            return;
          }
          const n = Number(next);
          if (Number.isInteger(n) && n >= 0 && n <= 4094) {
            onChange(n);
          }
        }}
        placeholder="例: 100"
        className={`w-full bg-slate-800 border rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-600 focus:outline-none ${
          valid ? 'border-slate-700 focus:border-emerald-500' : 'border-rose-500'
        }`}
      />
      {!valid && (
        <p className="text-[10px] text-rose-400 mt-1">
          0〜4094 の整数で入力してください
        </p>
      )}
    </div>
  );
}

function NetworkAddressInput({
  value,
  onChange,
}: {
  value: string;
  onChange: (val: string) => void;
}) {
  // 入力中の見た目を確定するためのローカル state。store には valid 値のみ反映。
  const [draft, setDraft] = useState(value);
  useEffect(() => {
    setDraft(value);
  }, [value]);
  const valid = isValidCidr(draft);
  return (
    <div>
      <label className="text-[10px] text-slate-400 font-bold block mb-1">
        Network Address (CIDR)
      </label>
      <input
        type="text"
        value={draft}
        onChange={(e) => {
          setDraft(e.target.value);
          if (isValidCidr(e.target.value)) {
            onChange(e.target.value.trim());
          }
        }}
        placeholder="例: 10.0.0.0/24"
        maxLength={64}
        className={`w-full bg-slate-800 border rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-600 focus:outline-none ${
          valid ? 'border-slate-700 focus:border-emerald-500' : 'border-rose-500'
        }`}
      />
      {!valid && (
        <p className="text-[10px] text-rose-400 mt-1">
          CIDR 形式で入力してください（例: 10.0.0.0/24）
        </p>
      )}
    </div>
  );
}

function MicroSection({
  boundary,
  onSelectMicro,
  onUpdateField,
}: {
  boundary: DiagramBoundary;
  onSelectMicro: (val: MicroTrustAttribute) => void;
  onUpdateField: <K extends keyof DiagramBoundary>(
    id: string,
    field: K,
    value: DiagramBoundary[K],
  ) => void;
}) {
  return (
    <>
      <section>
        <label className="text-[10px] font-black text-slate-500 uppercase flex items-center gap-2 mb-3">
          Trust Attribute
        </label>
        <div className="grid grid-cols-1 gap-2">
          {MICRO_TRUST_OPTIONS.map((opt) => (
            <button
              key={opt.val}
              onClick={() => onSelectMicro(opt.val)}
              className={`flex items-center gap-3 p-3 rounded-xl border transition-all text-xs font-bold ${
                boundary.microTrust === opt.val
                  ? 'bg-emerald-600 border-emerald-400 text-white'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              <span className={boundary.microTrust === opt.val ? 'text-white' : opt.color}>●</span>{' '}
              {opt.label}
            </button>
          ))}
        </div>
      </section>
      <section>
        <label className="text-[10px] font-black text-slate-500 uppercase flex items-center gap-2 mb-3">
          <ShieldCheck size={12} className="text-emerald-500" /> Micro Segmentation Status
        </label>
        <div className="grid grid-cols-2 gap-2">
          {MICRO_STATUS_OPTIONS.map((opt) => (
            <button
              key={opt.val}
              onClick={() => onUpdateField(boundary.id, 'microSegmentationStatus', opt.val)}
              className={`flex items-center gap-2 p-3 rounded-xl border transition-all text-xs font-bold ${
                boundary.microSegmentationStatus === opt.val
                  ? 'bg-emerald-600 border-emerald-400 text-white'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              <span
                className={boundary.microSegmentationStatus === opt.val ? 'text-white' : opt.color}
              >
                {opt.icon}
              </span>{' '}
              {opt.label}
            </button>
          ))}
        </div>
      </section>
      <section>
        <label className="text-[10px] font-black text-slate-500 uppercase flex items-center gap-2 mb-3">
          <Database size={12} className="text-emerald-500" /> Sensitive Data
        </label>
        <div className="grid grid-cols-1 gap-2">
          {SENSITIVE_DATA_OPTIONS.map((opt) => (
            <button
              key={opt.val}
              onClick={() => onUpdateField(boundary.id, 'sensitiveData', opt.val)}
              className={`flex items-center gap-3 p-3 rounded-xl border transition-all text-xs font-bold ${
                boundary.sensitiveData === opt.val
                  ? 'bg-emerald-600 border-emerald-400 text-white'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              <span className={boundary.sensitiveData === opt.val ? 'text-white' : opt.color}>
                {opt.icon}
              </span>{' '}
              {opt.label}
            </button>
          ))}
        </div>
      </section>
    </>
  );
}
