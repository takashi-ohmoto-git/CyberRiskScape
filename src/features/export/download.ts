/**
 * テキストをファイルとしてブラウザにダウンロードさせる（DOM 副作用）。
 *
 * `bom` を true にすると先頭に UTF-8 BOM を付与する。Excel が CSV を開く際に
 * 日本語を正しく解釈させるために CSV で使う。
 */
export function triggerDownload(
  filename: string,
  text: string,
  mime: string,
  bom = false,
): void {
  const BOM = '﻿';
  const parts = bom ? [BOM, text] : [text];
  const blob = new Blob(parts, { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
