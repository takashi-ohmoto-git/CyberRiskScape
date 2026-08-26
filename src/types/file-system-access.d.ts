/**
 * File System Access API のうち、標準 `lib.dom.d.ts`（TS 6.0）に未収録の
 * WICG 拡張部分だけを最小宣言する。
 *
 * - `FileSystemHandle.queryPermission` / `requestPermission`（権限の確認・要求）
 * - `Window.showDirectoryPicker`（ディレクトリ選択ダイアログ）
 *
 * `FileSystemDirectoryHandle` / `FileSystemFileHandle` / `createWritable` /
 * `values()` 等は lib.dom.d.ts 側に存在するため再宣言しない。
 * 非対応ブラウザでは実体が `undefined` のため、呼び出し側で存在チェックする。
 */

interface FileSystemHandlePermissionDescriptor {
  mode?: 'read' | 'readwrite';
}

interface FileSystemHandle {
  queryPermission?(descriptor?: FileSystemHandlePermissionDescriptor): Promise<PermissionState>;
  requestPermission?(descriptor?: FileSystemHandlePermissionDescriptor): Promise<PermissionState>;
}

interface DirectoryPickerOptions {
  id?: string;
  mode?: 'read' | 'readwrite';
  startIn?: FileSystemHandle | 'desktop' | 'documents' | 'downloads' | 'music' | 'pictures' | 'videos';
}

interface Window {
  showDirectoryPicker?(options?: DirectoryPickerOptions): Promise<FileSystemDirectoryHandle>;
}
