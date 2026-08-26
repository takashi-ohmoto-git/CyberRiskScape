import type { ElementKind } from './types';

/**
 * ElementalID の種別接頭辞（[[plan]] §2.26）。
 * - node     → `C`  （Component）
 * - edge     → `DF` （Data Flow）
 * - boundary → `Z`  （Zone / Trust Boundary）
 */
export const ELEMENTAL_ID_PREFIX: Record<ElementKind, string> = {
  node: 'C',
  edge: 'DF',
  boundary: 'Z',
};

/**
 * 種別と採番から表示用 ElementalID を整形する純粋関数（例：`('node', 3) → "C3"`）。
 * 採番自体は store が単調増加で行う（Step 2）。本関数は整形のみを担う。
 */
export function formatElementalId(kind: ElementKind, seq: number): string {
  return `${ELEMENTAL_ID_PREFIX[kind]}${seq}`;
}
