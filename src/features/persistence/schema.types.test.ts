/**
 * 型（`core/model/types.ts`）と保存スキーマ（`schema.ts`）の一致をコンパイル時に確かめる。
 *
 * 両者は二重に書いているので、型に値を足してスキーマを忘れると、その値を含む保存データが
 * 読み込みの検証に落ちる（IndexedDB のレコードは破棄される）。逆にスキーマだけ広げると、
 * 型に無い値がストアへ入る。どちらも `npx tsc --noEmit` で落とす。
 */
import { describe, expect, it } from 'vitest';
import type {
  Asset,
  BomComponent,
  ControlStatusState,
  Finding,
  LayerData,
  LayerKey,
  ManualThreat,
  ProjectMeta,
  RiskScore,
  SuppressionState,
} from '../../core/model/types';
import type { PersistedProject } from './schema';

/** A が B に代入できれば true。 */
type Assignable<A, B> = [A] extends [B] ? true : false;
/** 双方向に代入できれば true（保存できる値＝読み込める値）。never は不一致とする（参照先の取り違えで空振りさせない）。 */
type Same<A, B> = [A] extends [never] ? false : Assignable<A, B> extends true ? Assignable<B, A> : false;

type PersistedLayer = NonNullable<PersistedProject['layers']>['L1'];
type Item<T> = T extends readonly (infer U)[] ? U : never;

const same = <T extends true>(v: T): T => v;

describe('PersistedProjectSchema と型の一致', () => {
  it('図の要素・判断・指摘・資産・部品が、型とスキーマで双方向に代入できる', () => {
    const checks = [
      same<Same<Item<PersistedLayer['nodes']>, Item<LayerData['nodes']>>>(true),
      same<Same<Item<PersistedLayer['edges']>, Item<LayerData['edges']>>>(true),
      same<Same<Item<PersistedLayer['boundaries']>, Item<LayerData['boundaries']>>>(true),
      same<Same<Item<NonNullable<PersistedLayer['annotations']>>, Item<LayerData['annotations']>>>(true),
      same<Same<NonNullable<PersistedProject['activeLayer']>, LayerKey>>(true),
      same<Same<NonNullable<PersistedProject['projectMeta']>, ProjectMeta>>(true),
      same<Same<Item<NonNullable<PersistedProject['manualThreats']>['L1']>, ManualThreat>>(true),
      same<Same<NonNullable<PersistedProject['suppressions']>[string], SuppressionState>>(true),
      same<Same<NonNullable<PersistedProject['riskScores']>[string], RiskScore>>(true),
      same<Same<NonNullable<PersistedProject['controlStatuses']>[string], ControlStatusState>>(true),
      same<Same<Item<NonNullable<PersistedProject['findings']>>, Finding>>(true),
      same<Same<Item<NonNullable<PersistedProject['assets']>>, Asset>>(true),
      same<Same<Item<NonNullable<PersistedProject['bomComponents']>>, BomComponent>>(true),
    ];
    expect(checks.every(Boolean)).toBe(true);
  });
});
