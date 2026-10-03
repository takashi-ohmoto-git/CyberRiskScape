import { describe, expect, it } from 'vitest';
import { createCursor, layoutTableRow, wrapText, type Measure } from './layout';

// 全角（CJK）= size、半角 = size / 2 の疑似フォント。
const measure: Measure = (text, size) =>
  [...text].reduce((w, ch) => w + (ch.charCodeAt(0) > 0x2ff ? size : size / 2), 0);

describe('wrapText', () => {
  it('CJK は幅で任意位置で折り返す', () => {
    // 幅 50・size 10 → 全角 5 文字/行
    expect(wrapText('あいうえおかきくけこ', 50, 10, measure)).toEqual(['あいうえお', 'かきくけこ']);
  });

  it('ラテン語は空白で折り返し、行末の空白を落とす', () => {
    // 半角 5px/文字・幅 50 → 10 文字/行
    expect(wrapText('hello world foo', 50, 10, measure)).toEqual(['hello', 'world foo']);
  });

  it('幅を超える長い語は文字単位で強制分割する', () => {
    expect(wrapText('abcdefghijklmno', 50, 10, measure)).toEqual(['abcdefghij', 'klmno']);
  });

  it('\n は強制改行（空行も保持）', () => {
    expect(wrapText('a\n\nb', 100, 10, measure)).toEqual(['a', '', 'b']);
  });

  it('行頭禁則文字は前行にぶら下げる', () => {
    expect(wrapText('あいうえお。かき', 50, 10, measure)).toEqual(['あいうえお。', 'かき']);
  });

  it('空文字は 1 行の空行', () => {
    expect(wrapText('', 50, 10, measure)).toEqual(['']);
  });
});

describe('createCursor', () => {
  it('収まらなければ改ページして true を返す', () => {
    const c = createCursor(100, 10, 10);
    expect(c.y).toBe(90);
    expect(c.ensure(50)).toBe(false);
    c.advance(50);
    expect(c.ensure(30)).toBe(false); // 残り 40 → 下端 10 ちょうど
    expect(c.ensure(31)).toBe(true);
    expect(c.pageIndex).toBe(1);
    expect(c.y).toBe(90);
  });
});

describe('layoutTableRow', () => {
  it('最大セルの行数で高さが決まる', () => {
    const r = layoutTableRow(['あ', 'あいうえおかきくけこ'], [30, 30], 10, 12, 5, 3, measure);
    // 2 列目は内幅 20 → 2 文字/行 → 5 行
    expect(r.lines[1]).toHaveLength(5);
    expect(r.height).toBe(5 * 12 + 6);
  });

  it('maxLines を超えたら末尾に … を付けて打ち切る', () => {
    const r = layoutTableRow(['あいうえおかきくけこ'], [30], 10, 12, 5, 3, measure, 2);
    expect(r.lines[0]).toEqual(['あい', 'うえ…']);
  });
});
