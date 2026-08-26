import { useState } from 'react';
import { RotateCcw } from 'lucide-react';
import type { ControlStatusValue, ThreatView } from '../../core/model/types';
import { useDiagramStore } from '../../core/state/diagramStore';
import {
  CONTROL_STATUS_BADGE,
  CONTROL_STATUS_LABEL,
  CONTROL_STATUS_NOTE_REQUIRED,
  CONTROL_STATUS_ORDER,
} from './controlStatusStyle';

/**
 * 対策実装状況（Control Implementation Status）の編集フォーム。
 * リスク対応方針（suppression）とは別レイヤーとして、4 ステータス + note を記録する。
 *
 * - note 必須ステータス（implemented / not-applicable / rejected）は空欄では保存不可
 *   （保存ボタン無効化 + ヒント表示。ブラウザ標準ダイアログは使わない＝既存方針）。
 * - 脅威切替で draft を作り直すため、呼び出し側で key を threat.id に紐づけること。
 */
export function ControlStatusEditor({ threat }: { threat: ThreatView }) {
  const setControlStatus = useDiagramStore((s) => s.setControlStatus);
  const clearControlStatus = useDiagramStore((s) => s.clearControlStatus);

  const current = threat.controlStatus;
  const [status, setStatus] = useState<ControlStatusValue>(current?.status ?? 'required');
  const [note, setNote] = useState(current?.note ?? '');

  const noteRequired = CONTROL_STATUS_NOTE_REQUIRED[status];
  const trimmed = note.trim();
  const canSave = !noteRequired || trimmed !== '';

  return (
    <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-700 flex flex-col gap-2">
      {/* 現ステータス表示 */}
      <div className="flex items-center gap-2">
        <span className="text-[10px] text-slate-500">現在:</span>
        {current ? (
          <span
            className={`text-[10px] px-2 py-0.5 rounded border ${CONTROL_STATUS_BADGE[current.status]}`}
          >
            {CONTROL_STATUS_LABEL[current.status]}
          </span>
        ) : (
          <span className="text-[10px] px-2 py-0.5 rounded border border-slate-700 text-slate-500">
            未設定
          </span>
        )}
      </div>

      {/* ステータスセレクタ */}
      <div className="flex flex-wrap gap-1.5">
        {CONTROL_STATUS_ORDER.map((v) => (
          <button
            key={v}
            onClick={() => setStatus(v)}
            className={`text-[10px] px-2.5 py-1 rounded border transition-colors ${
              status === v
                ? CONTROL_STATUS_BADGE[v]
                : 'border-slate-700 text-slate-500 hover:text-slate-300 hover:border-slate-500'
            }`}
          >
            {CONTROL_STATUS_LABEL[v]}
          </button>
        ))}
      </div>

      <textarea
        rows={2}
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder={noteRequired ? '理由・実装方法を記録（必須）' : '補足（任意）'}
        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-blue-500 resize-y"
      />

      <div className="flex items-center gap-2">
        {noteRequired && !canSave && (
          <span className="text-[9px] text-amber-300/80">
            「{CONTROL_STATUS_LABEL[status]}」は note が必須です。
          </span>
        )}
        <div className="flex gap-2 ml-auto">
          {current && (
            <button
              onClick={() => clearControlStatus(threat.id)}
              className="flex items-center gap-1 text-[10px] px-2.5 py-1 rounded border border-slate-700 text-slate-500 hover:text-slate-200 hover:border-slate-500 transition-colors"
            >
              <RotateCcw size={11} /> 解除
            </button>
          )}
          <button
            onClick={() => setControlStatus(threat.id, status, trimmed === '' ? undefined : trimmed)}
            disabled={!canSave}
            className="text-[10px] px-2.5 py-1 rounded bg-emerald-500/20 border border-emerald-500/40 text-emerald-200 hover:bg-emerald-500/30 transition-colors disabled:opacity-40 disabled:hover:bg-emerald-500/20"
          >
            保存
          </button>
        </div>
      </div>
    </div>
  );
}
