import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

/**
 * SCAP の結果の指摘 → canonicalId の対応表（`data/finding-maps/xccdf.yaml`）。
 * 脅威知識はコードに置かず YAML に置く。
 */

const XccdfMapSchema = z.object({
  schemaVersion: z.literal(1),
  rules: z.record(
    z.string().min(1),
    z.object({ canonicalIds: z.array(z.string().min(1)).nonempty(), note: z.string().optional() }),
  ),
  ovalClasses: z.record(z.string().min(1), z.array(z.string().min(1)).nonempty()),
});

export interface XccdfMap {
  rules: Record<string, { canonicalIds: string[]; note?: string }>;
  ovalClasses: Record<string, string[]>;
}

/** YAML のキー重複は yaml パッケージが例外にする（エラーを日本語に包む）。 */
export function loadXccdfMap(text: string): XccdfMap {
  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch (e) {
    throw new Error(`[xccdf-map] YAML を読めません（キーの重複を含む）: ${e instanceof Error ? e.message : String(e)}`, { cause: e });
  }
  const m = XccdfMapSchema.parse(raw);
  return { rules: m.rules, ovalClasses: m.ovalClasses };
}

const RULE_PREFIX = 'xccdf_org.ssgproject.content_rule_';

/** XCCDF の idref から ComplianceAsCode の短いルール名を引き、canonicalId を返す。無ければ空配列。 */
export function xccdfRuleToCanonicalIds(map: XccdfMap, idref: string): string[] {
  const short = idref.startsWith(RULE_PREFIX) ? idref.slice(RULE_PREFIX.length) : idref;
  return map.rules[short]?.canonicalIds ?? [];
}

// ── 同梱データ（Vite の import.meta.glob で raw 文字列として取り込む。CLI ビルド・Vitest でも動く）──

const sources = import.meta.glob<string>('../../../data/finding-maps/xccdf.yaml', {
  query: '?raw',
  import: 'default',
  eager: true,
});

export const BUNDLED_XCCDF_MAP: XccdfMap = loadXccdfMap(
  Object.values(sources)[0] ?? 'schemaVersion: 1\nrules: {}\novalClasses: {}\n',
);
