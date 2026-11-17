/**
 * 画面を別のページに組み込むための入口（ブラウザ用）。
 *
 * アプリ本体（`App`）と、プロジェクトの保存先の差し替え（`setProjectStorage`）だけを出す。
 * 組み込む側は、`App` を描画する前に保存先を差し替える。差し替えなければ、保存先はブラウザの IndexedDB のまま。
 * スタイル（`src/index.css`。Tailwind）は組み込む側で読み込む。
 *
 * 画面を通さない関数の入口は `./index.ts`（こちらは DOM・IndexedDB に依存しない）。
 * ここから出す名前は、外から使われる前提で保つ。
 */
export { default as App } from '../App';
export {
  setProjectStorage,
  type ProjectStorage,
  type SaveTrigger,
} from '../features/persistence/storage';
// 組み込む側が、開く前に内容を確かめるための検証（通らなければ null。そのまま渡すと既定のサンプルで始まる）
export { deserializeProject } from '../features/persistence/serialize';
export type { PersistedProject } from '../features/persistence/schema';
