/**
 * 古典 DFD（Yourdon 記法）で描くカテゴリ。
 * このカテゴリの型はキャンバス上でアイコンを描かず、形の中央にラベルだけを置く。
 * 判定は shape ではなくカテゴリで行う（data-store 形は AI の MEMORY_STORE も使うため）。
 */
export const DFD_NOTATION_CATEGORIES: ReadonlySet<string> = new Set(['CLASSIC_DFD']);

export function isDfdNotationCategory(category: string | undefined): boolean {
  return category !== undefined && DFD_NOTATION_CATEGORIES.has(category);
}
