import { useState } from 'react';
import { RotateCcw } from 'lucide-react';
import type { SuppressionStatus, ThreatView } from '../../core/model/types';
import { useDiagramStore } from '../../core/state/diagramStore';
import {
  RISK_TREATMENT_BADGE,
  RISK_TREATMENT_LABEL,
  RISK_TREATMENT_ORDER,
} from './riskTreatmentStyle';

/**
 * リスク対応方針（Risk Treatment）の編集フォーム。
 * 対策実装状況（controlStatus）とは別レイヤーとして、5 方針 + note を記録する。
 *
 * - note は全方針で任意（必須なし。保存ボタン常時有効）。
 * - 受容 / 誤検知 のみ「抑制」（淡色化・件数/バッジ除外）扱い、
 *   回避 / 低減 / 移転 は表示・カウントを維持する。
 * - 脅威切替で draft を作り直すため、呼び出し側で key を threat.id に紐づけること。
 */
export function RiskTreatmentEditor({ threat }: { threat: ThreatView }) {
  const setSuppression = useDiagramStore((s) => s.setSuppression);
  const clearSuppression = useDiagramStore((s) => s.clearSuppression);

  const current = threat.suppression;
  const [status, setStatus] = useState<SuppressionStatus>(current?.status ?? 'reduce');
  const [note, setNote] = useState(current?.note ?? '');

  const trimmed = note.trim();

  return (
    <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-700 flex flex-col gap-2">
      {/* 現方針表示 */}
      <div className="flex items-center gap-2">
        <span className="text-[10px] text-slate-500">現在:</span>
        {current ? (
          <span
            className={`text-[10px] px-2 py-0.5 rounded border ${RISK_TREATMENT_BADGE[current.status]}`}
          >
            {RISK_TREATMENT_LABEL[current.status]}
          </span>
        ) : (
          <span className="text-[10px] px-2 py-0.5 rounded border border-slate-700 text-slate-500">
            未設定
          </span>
        )}
      </div>

      {/* 方針セレクタ */}
      <div className="flex flex-wrap gap-1.5">
        {RISK_TREATMENT_ORDER.map((v) => (
          <button
            key={v}
            onClick={() => setStatus(v)}
            className={`text-[10px] px-2.5 py-1 rounded border transition-colors ${
              status === v
                ? RISK_TREATMENT_BADGE[v]
                : 'border-slate-700 text-slate-500 hover:text-slate-300 hover:border-slate-500'
            }`}
          >
            {RISK_TREATMENT_LABEL[v]}
          </button>
        ))}
      </div>

      <textarea
        rows={2}
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="判断の根拠・残留リスクの補足など（任意）"
        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 resize-y"
      />

      <div className="flex items-center gap-2">
        <div className="flex gap-2 ml-auto">
          {current && (
            <button
              onClick={() => clearSuppression(threat.id)}
              className="flex items-center gap-1 text-[10px] px-2.5 py-1 rounded border border-slate-700 text-slate-500 hover:text-slate-200 hover:border-slate-500 transition-colors"
            >
              <RotateCcw size={11} /> 解除
            </button>
          )}
          <button
            onClick={() => setSuppression(threat.id, status, trimmed === '' ? undefined : trimmed)}
            className="text-[10px] px-2.5 py-1 rounded bg-emerald-500/20 border border-emerald-500/40 text-emerald-200 hover:bg-emerald-500/30 transition-colors"
          >
            保存
          </button>
        </div>
      </div>
    </div>
  );
}
