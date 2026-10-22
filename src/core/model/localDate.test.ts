import { describe, expect, it } from 'vitest';
import { formatLocalDate } from './localDate';

describe('formatLocalDate', () => {
  it('実行環境のタイムゾーンの年月日を返す（UTC ではない）', () => {
    const d = new Date(2026, 9, 23, 1, 30); // ローカル時刻 2026-10-23 01:30
    expect(formatLocalDate(d)).toBe('2026-10-23');
  });

  it('月日を 2 桁にそろえる', () => {
    expect(formatLocalDate(new Date(2026, 0, 5, 12))).toBe('2026-01-05');
  });
});
