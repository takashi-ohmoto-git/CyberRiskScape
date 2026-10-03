import regularUrl from '../../assets/fonts/BIZUDPGothic-Regular.ttf?url';
import boldUrl from '../../assets/fonts/BIZUDPGothic-Bold.ttf?url';
import wasmUrl from 'harfbuzzjs/dist/harfbuzz-subset.wasm?url';
import { version } from '../../../package.json';

/**
 * PDF 生成用アセット（フォント・HarfBuzz wasm）と版番号。
 * `exportFiles` から動的 import され、初期バンドルには入らない（URL は別アセットとして出力される）。
 */

async function fetchBytes(url: string): Promise<Uint8Array> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`asset fetch failed: ${url} (${res.status})`);
  return new Uint8Array(await res.arrayBuffer());
}

export const APP_VERSION: string = version;

export async function loadPdfAssets(): Promise<{
  fonts: { regular: Uint8Array; bold: Uint8Array };
  harfbuzzWasm: Uint8Array;
}> {
  const [regular, bold, harfbuzzWasm] = await Promise.all([
    fetchBytes(regularUrl),
    fetchBytes(boldUrl),
    fetchBytes(wasmUrl),
  ]);
  return { fonts: { regular, bold }, harfbuzzWasm };
}
