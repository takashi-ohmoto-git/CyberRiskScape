import {
  normalizeScopeValue,
  type ServiceScopeEntry,
} from '../../core/model/serviceScope';

/**
 * Project Edit の「担当範囲」入力欄の検証と保存用の変換。コンポーネントの外に出した純粋関数。
 */

export const MAX_SERVICE_SCOPE_ENTRIES = 200;

/** 値が空でなく、解釈できない行の添字。 */
export function findInvalidScopeRows(rows: readonly ServiceScopeEntry[]): number[] {
  const bad: number[] = [];
  rows.forEach((r, i) => {
    const v = r.value.trim();
    if (v !== '' && normalizeScopeValue(r.kind, v) === undefined) bad.push(i);
  });
  return bad;
}

/** 保存用：空の行を捨て、前後の空白を除く（値は正規化しない）。0 件なら undefined。 */
export function toSavedServiceScope(
  rows: readonly ServiceScopeEntry[] | undefined,
): ServiceScopeEntry[] | undefined {
  const out: ServiceScopeEntry[] = [];
  for (const r of rows ?? []) {
    const value = r.value.trim();
    if (value === '') continue;
    const note = r.note?.trim();
    out.push(note ? { kind: r.kind, value, note } : { kind: r.kind, value });
  }
  return out.length > 0 ? out : undefined;
}
