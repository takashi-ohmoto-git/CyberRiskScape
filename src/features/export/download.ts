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

/** バイナリ（PNG・PDF 等）をファイルとしてブラウザにダウンロードさせる（DOM 副作用）。 */
export function triggerBlobDownload(filename: string, bytes: Uint8Array, mime: string): void {
  const blob = new Blob([bytes as BlobPart], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // 即 revoke すると大きなファイルのダウンロードが始まる前に失効し得るため遅延させる。
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
