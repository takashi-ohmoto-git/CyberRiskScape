import { z } from 'zod';
import { CRYPTO_TERMINATIONS } from '../core/model/types';

/**
 * 暗号の終端判定の既定値（`data/crypto-behavior/termination.yaml`）と
 * PQC 判定の基準表（`pqc-algorithms.yaml`）のスキーマ。
 * 設計は docs/pqc-path-analysis.md §6 / §7-4。
 */

const TerminationSchema = z.enum(CRYPTO_TERMINATIONS);

export const TerminationBehaviorSchema = z
  .object({
    componentType: z.string().min(1),
    default: TerminationSchema,
    alternatives: z.array(TerminationSchema),
    note: z.string().min(1),
  })
  .strict()
  .refine((b) => !b.alternatives.includes(b.default), {
    message: 'alternatives に default を含めることはできません',
    path: ['alternatives'],
  });

export const TerminationFileSchema = z
  .object({
    schemaVersion: z.literal(1),
    behaviors: z.array(TerminationBehaviorSchema),
  })
  .strict();

/** 翻訳オーバーレイ。`note` のみ翻訳対象で、componentType を鍵にする。 */
export const TerminationOverlayFileSchema = z
  .object({
    schemaVersion: z.literal(1),
    locale: z.string().min(2),
    behaviors: z.record(z.string(), z.object({ note: z.string().min(1).optional() }).strict()),
  })
  .strict();

export const ALGORITHM_CLASSES = ['pqc', 'transitional', 'vulnerable'] as const;
export const AlgorithmClassSchema = z.enum(ALGORITHM_CLASSES);

const TokensSchema = z.object({ tokens: z.array(z.string().min(1)).min(1) }).strict();

export const AlgorithmTableSchema = z
  .object({
    schemaVersion: z.literal(1),
    /** 複数の分類に当たったとき、先頭から順に採用する。 */
    priority: z.array(AlgorithmClassSchema).length(ALGORITHM_CLASSES.length),
    classes: z
      .object({ pqc: TokensSchema, transitional: TokensSchema, vulnerable: TokensSchema })
      .strict(),
  })
  .strict()
  .refine((t) => new Set(t.priority).size === ALGORITHM_CLASSES.length, {
    message: 'priority は 3 分類を 1 回ずつ含める必要があります',
    path: ['priority'],
  });

export type TerminationBehavior = z.infer<typeof TerminationBehaviorSchema>;
export type TerminationOverlay = z.infer<typeof TerminationOverlayFileSchema>['behaviors'];
export type AlgorithmClass = z.infer<typeof AlgorithmClassSchema>;
export type AlgorithmTable = z.infer<typeof AlgorithmTableSchema>;
