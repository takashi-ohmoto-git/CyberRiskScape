import type { Framework, FrameworkView } from '../core/model/types';

/**
 * CANVAS のフレームワーク切替タブ。`'ALL'` を既定の先頭に置く。
 * データ層の `Framework` 値は不変で、ここは表示順とラベルのみを定義する。
 */
export const FRAMEWORK_VIEWS: FrameworkView[] = ['ALL', 'STRIDE', 'AI', 'AgenticAI'];

/**
 * タブ／バッジの表示ラベル。古典的な人間中心 STRIDE → AI/LLM → エージェント中心という
 * 成熟度の対比を表現する。STRIDE のみ権威付けで元フレームワーク名を併記し、AI/AgenticAI は
 * 特定フレームワークではなく概念カテゴリのため併記しない。
 */
export const FRAMEWORK_VIEW_LABELS: Record<FrameworkView, string> = {
  ALL: 'ALL',
  STRIDE: 'Human Centric (STRIDE)',
  AI: 'AI・LLM',
  AgenticAI: 'Agent-Centric',
};

/** 手動脅威作成ピッカーの選択肢（具体的な `Framework` 値のみ。`'ALL'` は含めない）。 */
export const MANUAL_THREAT_FRAMEWORKS: Framework[] = ['STRIDE', 'AI', 'AgenticAI'];
