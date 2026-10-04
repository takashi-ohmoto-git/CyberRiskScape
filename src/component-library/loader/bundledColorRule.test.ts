import { describe, expect, it } from 'vitest';
import { BUNDLED_COMPONENT_LIBRARY } from './bundledComponentLibrary';

/**
 * 同梱ライブラリの背景色ルール。
 *
 * 色は「型」ではなく「カテゴリ」を表す。同じカテゴリの型はすべて同じ色にする。
 * 視覚的に把握すべきカテゴリだけを有色にし、それ以外は `bg-transparent`。
 * 赤・橙・青系は重大度や認証マーカーの意味と衝突するため、ATTACKER の赤以外は使わない。
 */
const CATEGORY_COLORS: Record<string, string> = {
  ATTACKER: 'bg-red-600',
  USERS_DEVICES: 'bg-yellow-600',
  PROTECT: 'bg-green-600',
  IDENTITY: 'bg-fuchsia-600',
  AI: 'bg-violet-600',
  DOCUMENTS: 'bg-cyan-600',
};
const UNCOLORED = 'bg-transparent';

describe('同梱コンポーネントの背景色ルール', () => {
  it.each(BUNDLED_COMPONENT_LIBRARY.components.map((c) => [c.id, c.category, c.color] as const))(
    '%s（%s）はカテゴリの色に従う',
    (_id, category, color) => {
      expect(color).toBe(CATEGORY_COLORS[category] ?? UNCOLORED);
    },
  );
});
