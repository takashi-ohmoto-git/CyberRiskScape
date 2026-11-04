/**
 * purl（Package URL）の組み立てと正規化。部品の同一判定の鍵に使う純粋関数。
 * 仕様：https://github.com/package-url/purl-spec
 */

/** purl の版を付けてよい「固定された版」か。範囲指定（^ ~ >= * 等）は false。 */
export function isExactVersion(version: string, pinned: boolean | undefined): boolean {
  return pinned !== false && /^\d[0-9A-Za-z.+_!-]*$/.test(version);
}

export function purlOf(kind: 'npm' | 'pypi', name: string, version?: string): string {
  const v = version ? `@${encodeURIComponent(version)}` : '';
  if (kind === 'npm') {
    const n = name.startsWith('@') ? `%40${name.slice(1)}` : name;
    return `pkg:npm/${n}${v}`;
  }
  return `pkg:pypi/${name.toLowerCase().replace(/_/g, '-')}${v}`;
}

/** 修飾子（?）とサブパス（#）を除く。修飾子には取得元の URL が入ることがあるので保存しない。 */
export function stripPurl(purl: string): string {
  return purl.split(/[?#]/)[0];
}
