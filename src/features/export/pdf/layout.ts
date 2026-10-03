/**
 * PDF レイアウトの純粋ヘルパー（フォント非依存。幅は `measure` を注入する）。
 */

/** 文字列の描画幅（pt）。`\n` を含まない 1 行分が渡される。 */
export type Measure = (text: string, size: number) => number;

/** 行頭に置かない文字（簡易禁則）。 */
const NO_LINE_START = new Set('、。，．,.」』）〕】》〉・：；？！ー々ゝゞぁぃぅぇぉっゃゅょァィゥェォッャュョ)]}!?:;%'.split(''));

const CJK_RE = /[\u3000-\u30ff\u3400-\u9fff\uf900-\ufaff\uff00-\uffef]/;

/** 折返しの最小単位に分割する：CJK は 1 文字、ラテン語は連続する非空白＋空白。 */
function tokenize(line: string): string[] {
  const tokens: string[] = [];
  let word = '';
  const flush = () => {
    if (word) tokens.push(word);
    word = '';
  };
  for (const ch of line) {
    if (CJK_RE.test(ch)) {
      flush();
      tokens.push(ch);
    } else if (ch === ' ') {
      flush();
      tokens.push(ch);
    } else {
      word += ch;
    }
  }
  flush();
  return tokens;
}

/**
 * 幅 `maxWidth` に収まるよう折り返す。`\n` は強制改行。
 * CJK はどこでも改行可（行頭禁則文字は前行へぶら下げる）、ラテン語は空白で改行し、
 * 1 語が幅を超えるときは文字単位で強制分割する。
 */
export function wrapText(text: string, maxWidth: number, size: number, measure: Measure): string[] {
  const out: string[] = [];
  for (const rawLine of text.replace(/\r\n?/g, '\n').split('\n')) {
    let cur = '';
    let curW = 0;
    const push = () => {
      out.push(cur.replace(/ +$/, ''));
      cur = '';
      curW = 0;
    };
    for (const tok of tokenize(rawLine)) {
      const w = measure(tok, size);
      if (tok === ' ' && cur === '') continue; // 行頭の空白は捨てる
      if (curW + w <= maxWidth) {
        cur += tok;
        curW += w;
        continue;
      }
      // 行頭禁則：1 文字で禁則文字なら今の行にぶら下げる
      if (cur !== '' && tok.length === 1 && NO_LINE_START.has(tok)) {
        cur += tok;
        curW += w;
        continue;
      }
      if (tok === ' ') {
        push();
        continue;
      }
      if (cur !== '') push();
      if (w <= maxWidth) {
        cur = tok;
        curW = w;
        continue;
      }
      // 1 語が幅超過：文字単位で強制分割
      for (const ch of tok) {
        const cw = measure(ch, size);
        if (cur !== '' && curW + cw > maxWidth) push();
        cur += ch;
        curW += cw;
      }
    }
    push();
  }
  return out;
}

/** 縦方向カーソル。`y` は PDF 座標（下原点）での「次に描ける上端」。 */
export interface PageCursor {
  pageIndex: number;
  y: number;
  /** `height` が現ページに収まらなければ改ページして true を返す。 */
  ensure(height: number): boolean;
  /** 下へ `height` 進める。 */
  advance(height: number): void;
}

export function createCursor(pageHeight: number, marginTop: number, marginBottom: number): PageCursor {
  const cursor: PageCursor = {
    pageIndex: 0,
    y: pageHeight - marginTop,
    ensure(height) {
      if (cursor.y - height >= marginBottom) return false;
      cursor.pageIndex += 1;
      cursor.y = pageHeight - marginTop;
      return true;
    },
    advance(height) {
      cursor.y -= height;
    },
  };
  return cursor;
}

export interface TableRowLayout {
  /** セルごとの折返し済み行。 */
  lines: string[][];
  /** 行の高さ（上下パディング込み）。 */
  height: number;
}

/**
 * 表の 1 行分を折り返し、最大セルに合わせた高さを返す。
 * `maxLines` を超えた分は末尾を「…」で打ち切る（1 行が 1 ページを超える事故の防止）。
 */
export function layoutTableRow(
  cells: string[],
  widths: number[],
  size: number,
  lineHeight: number,
  padX: number,
  padY: number,
  measure: Measure,
  maxLines = 8,
): TableRowLayout {
  const lines = cells.map((text, i) => {
    const wrapped = wrapText(text, Math.max(1, (widths[i] ?? 0) - padX * 2), size, measure);
    if (wrapped.length <= maxLines) return wrapped;
    const cut = wrapped.slice(0, maxLines);
    cut[maxLines - 1] = `${cut[maxLines - 1]}…`;
    return cut;
  });
  const maxCount = Math.max(1, ...lines.map((l) => l.length));
  return { lines, height: maxCount * lineHeight + padY * 2 };
}
