/**
 * HarfBuzz（harfbuzz-subset.wasm）による実行時フォントサブセット。
 *
 * pdf-lib の `embedFont(..., { subset: true })` は日本語グリフが欠落するため、
 * 文書で使う文字だけをここで切り出し、`subset: false` で埋め込む。
 * wasm は import 無しの単体モジュール。バイト列は呼び出し側が注入する（fetch しない）。
 */

/** 使う HarfBuzz エクスポートだけの型。ポインタ・ハンドルはすべて number。 */
interface HbExports {
  memory: WebAssembly.Memory;
  malloc(size: number): number;
  free(ptr: number): void;
  hb_blob_create(data: number, length: number, mode: number, userData: number, destroy: number): number;
  hb_blob_destroy(blob: number): void;
  hb_blob_get_data(blob: number, lengthPtr: number): number;
  hb_blob_get_length(blob: number): number;
  hb_face_create(blob: number, index: number): number;
  hb_face_destroy(face: number): void;
  hb_face_reference_blob(face: number): number;
  hb_subset_input_create_or_fail(): number;
  hb_subset_input_destroy(input: number): void;
  hb_subset_input_unicode_set(input: number): number;
  hb_subset_or_fail(face: number, input: number): number;
  hb_set_add(set: number, codepoint: number): void;
}

/** `hb_blob_create` の mode：WRITABLE（wasm 側のコピーを書き換え可）。 */
const HB_MEMORY_MODE_WRITABLE = 2;

/** 常に残す文字（ASCII 印字可能文字 ＋ 本文で使う記号）。 */
const ALWAYS_KEEP = (() => {
  let s = '';
  for (let c = 0x20; c <= 0x7e; c++) s += String.fromCharCode(c);
  return s + '…—–·・';
})();

export interface FontSubsetter {
  /** `text` に含まれる文字（＋ ASCII 印字可能文字）だけを残した TrueType を返す。 */
  subset(fontBytes: Uint8Array, text: string): Uint8Array;
}

/** wasm をインスタンス化する。同一エクスポート内で複数ウェイトに使い回す。 */
export async function createFontSubsetter(wasmBytes: ArrayBuffer | Uint8Array): Promise<FontSubsetter> {
  const { instance } = await WebAssembly.instantiate(wasmBytes as BufferSource);
  const ex = instance.exports as unknown as HbExports;

  return {
    subset(fontBytes, text) {
      // memory.buffer は malloc で伸びると差し替わるので、使う直前に取り直す。
      const heap = () => new Uint8Array(ex.memory.buffer);
      const ptr = ex.malloc(fontBytes.byteLength);
      let blob = 0;
      let face = 0;
      let input = 0;
      let sub = 0;
      let outBlob = 0;
      try {
        heap().set(fontBytes, ptr);
        blob = ex.hb_blob_create(ptr, fontBytes.byteLength, HB_MEMORY_MODE_WRITABLE, 0, 0);
        face = ex.hb_face_create(blob, 0);
        input = ex.hb_subset_input_create_or_fail();
        if (!input) throw new Error('hb_subset_input_create failed');
        const uset = ex.hb_subset_input_unicode_set(input);
        for (const ch of new Set(ALWAYS_KEEP + text)) {
          ex.hb_set_add(uset, ch.codePointAt(0) as number);
        }
        sub = ex.hb_subset_or_fail(face, input);
        if (!sub) throw new Error('hb_subset failed');
        outBlob = ex.hb_face_reference_blob(sub);
        const off = ex.hb_blob_get_data(outBlob, 0);
        const len = ex.hb_blob_get_length(outBlob);
        return heap().slice(off, off + len);
      } finally {
        if (outBlob) ex.hb_blob_destroy(outBlob);
        if (sub) ex.hb_face_destroy(sub);
        if (input) ex.hb_subset_input_destroy(input);
        if (face) ex.hb_face_destroy(face);
        if (blob) ex.hb_blob_destroy(blob);
        ex.free(ptr);
      }
    },
  };
}

/** 1 回きりの利用向けの薄いラッパー。 */
export async function subsetFont(
  wasmBytes: ArrayBuffer | Uint8Array,
  fontBytes: Uint8Array,
  text: string,
): Promise<Uint8Array> {
  return (await createFontSubsetter(wasmBytes)).subset(fontBytes, text);
}
