/**
 * 観測した API の要求（メソッド＋URL）が、API の定義（メソッド＋URL のテンプレート）に当たるかを判定する。
 * - scheme・ホスト・ポート（既定のポートは除く）が同じで、パスの区切りの数が同じ
 * - テンプレートの `{名前}` を含む区切りは、その部分を任意の文字列（区切りの `/` を除く）とみなす
 * - クエリ・フラグメント・末尾の `/` は無視する。メソッドは大文字小文字を区別しない
 * DOM にも Node にも依存しない純粋関数。
 */

const DEFAULT_PORTS: Record<string, string> = { http: '80', https: '443' };

interface SplitUrl {
  origin: string;
  segments: string[];
}

function split(url: string): SplitUrl | undefined {
  const m = /^([a-z][a-z0-9+.-]*):\/\/(?:[^@/?#]*@)?([^/?#]+)([^?#]*)/i.exec(url.trim());
  if (!m) return undefined;
  const scheme = m[1].toLowerCase();
  let host = m[2].toLowerCase();
  const port = /:(\d+)$/.exec(host)?.[1];
  if (port !== undefined && port === DEFAULT_PORTS[scheme]) host = host.slice(0, -port.length - 1);
  const segments = m[3].split('/').filter((s) => s !== '');
  return { origin: `${scheme}://${host}`, segments };
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function segmentMatches(template: string, actual: string): boolean {
  if (!template.includes('{')) {
    let decoded = actual;
    try {
      decoded = decodeURIComponent(actual);
    } catch {
      // 不正なエスケープはそのまま比べる
    }
    return template === actual || template === decoded;
  }
  const re = new RegExp(`^${template.split(/\{[^}]*\}/).map(escape).join('[^/]+')}$`);
  return re.test(actual);
}

export function matchesApiDefinition(
  observed: { method?: string; url: string },
  definition: { method?: string; url: string },
): boolean {
  if (observed.method && definition.method && observed.method.toUpperCase() !== definition.method.toUpperCase()) return false;
  const o = split(observed.url);
  const d = split(definition.url);
  if (!o || !d || o.origin !== d.origin || o.segments.length !== d.segments.length) return false;
  return d.segments.every((t, i) => segmentMatches(t, o.segments[i]));
}
