import { z } from 'zod';

/**
 * Postman Collection を DAST ツール（Veracode DAST API スキャン等）の入力にするための加工。
 *
 * - `applyVariableValues`：`--vars` の値をコレクション変数へ埋める。
 * - `filterByBaseUrl`：`--base-url` 配下へのリクエストだけを残す（DAST は base URL 配下のみ走査するため）。
 *
 * どちらも入力を変更しない純関数。変数の値は戻り値のコレクションにだけ入り、ログには出さない。
 */

type Collection = Record<string, unknown>;

interface Variable {
  key: string;
  value: string;
  description?: string;
}

interface RequestItem {
  name: string;
  request?: { url?: unknown };
  item?: RequestItem[];
  [k: string]: unknown;
}

/** `--vars` ファイルの形式：文字列だけを値に持つ平らなオブジェクト。 */
export const VarsFileSchema = z.record(z.string(), z.string());

const variablesOf = (c: Collection): Variable[] => (Array.isArray(c.variable) ? (c.variable as Variable[]) : []);
const itemsOf = (c: Collection): RequestItem[] => (Array.isArray(c.item) ? (c.item as RequestItem[]) : []);

/**
 * コレクション変数の `value` を `values` で上書きする。
 * コレクションに無いキーは `unknownKeys`、埋めた `token_` 始まりのキーは `filledTokenKeys` に返す（キーのみ）。
 */
export function applyVariableValues(
  collection: Collection,
  values: Record<string, string>,
): { collection: Collection; unknownKeys: string[]; filledTokenKeys: string[] } {
  const known = new Set(variablesOf(collection).map((v) => v.key));
  const variable = variablesOf(collection).map((v) =>
    Object.prototype.hasOwnProperty.call(values, v.key) ? { ...v, value: values[v.key] } : v,
  );
  const keys = Object.keys(values);
  return {
    collection: { ...collection, variable },
    unknownKeys: keys.filter((k) => !known.has(k)),
    filledTokenKeys: keys.filter((k) => known.has(k) && k.startsWith('token_')),
  };
}

/** `{{key}}` を変数の値で置き換える（入れ子の参照を解くため、変化しなくなるまで最大 5 回）。 */
function resolve(text: string, vars: Map<string, string>): string {
  let cur = text;
  for (let i = 0; i < 5; i++) {
    const next = cur.replace(/\{\{([^{}]+)\}\}/g, (m, k: string) => vars.get(k) ?? m);
    if (next === cur) break;
    cur = next;
  }
  return cur;
}

/** 解決後の URL が base URL 配下か。`https://a.com` が `https://a.com.evil.net` に当たらないよう、直後は終端・`/`・`?` に限る。 */
function isUnder(url: string, base: string): boolean {
  if (!url.startsWith(base)) return false;
  const next = url.charAt(base.length);
  return next === '' || next === '/' || next === '?';
}

function urlOf(item: RequestItem): string {
  const u = item.request?.url;
  if (typeof u === 'string') return u;
  if (u && typeof u === 'object' && typeof (u as { raw?: unknown }).raw === 'string') return (u as { raw: string }).raw;
  return '';
}

/**
 * base URL 配下へのリクエストだけを残す。URL は変数のテンプレートのまま保つ（判定時のみ値を解決する）。
 * 空になったフォルダと、残ったリクエストから参照されなくなった変数（他の変数の値を介した参照を含む）は除く。
 */
export function filterByBaseUrl(
  collection: Collection,
  baseUrl: string,
): { collection: Collection; kept: number; total: number } {
  const base = baseUrl.replace(/\/+$/, '');
  const vars = variablesOf(collection);
  const values = new Map(vars.map((v) => [v.key, v.value]));
  let total = 0;
  let kept = 0;

  const walk = (items: RequestItem[]): RequestItem[] => {
    const out: RequestItem[] = [];
    for (const it of items) {
      if (Array.isArray(it.item)) {
        const children = walk(it.item);
        if (children.length > 0) out.push({ ...it, item: children });
      } else if (it.request) {
        total++;
        if (isUnder(resolve(urlOf(it), values), base)) {
          kept++;
          out.push(it);
        }
      }
    }
    return out;
  };
  const item = walk(itemsOf(collection));

  // 参照されている変数を、他の変数の値を介した参照も含めて集める（`{{key}}` と `pm.variables.get("key")`）。
  const isReferenced = (text: string, key: string): boolean =>
    text.includes(`{{${key}}}`) || new RegExp(String.raw`pm\.variables\.get\(\\?["']${key}\\?["']\)`).test(text);
  let text = JSON.stringify(item);
  const used = new Set<string>();
  for (let changed = true; changed; ) {
    changed = false;
    for (const v of vars) {
      if (!used.has(v.key) && isReferenced(text, v.key)) {
        used.add(v.key);
        text += `\n${v.value}`;
        changed = true;
      }
    }
  }

  return { collection: { ...collection, variable: vars.filter((v) => used.has(v.key)), item }, kept, total };
}
