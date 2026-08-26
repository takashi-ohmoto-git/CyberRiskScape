import type { MitigationTiers } from '../schema/threatRule';

/**
 * `mitigation` 文字列から `[Foundation]` / `[Enterprise]` / `[Advanced]` の
 * インライン markup を抽出し、3 段階構造化された `MitigationTiers` を返す。
 *
 * 仕様（docs/threat-schema.md §7.5.1）：
 * - タグは `[Foundation]` `[Enterprise]` `[Advanced]`（大文字小文字無視）。
 * - 各タグから次のタグまでをそれぞれの値として抽出。前後空白は trim。
 * - 順序は前後しても OK（タグ名で識別）。
 * - 同一タグの複数指定は **後勝ち** + console.warn。
 * - markup の前にあるテキスト（プレフィックス）は無視される（生 `mitigation` 文字列のみに残る）。
 * - markup を 1 つも含まない、または `text` が undefined のときは `undefined` を返す。
 *
 * 純粋関数（console.warn を除く）。ローダーとテストから共有。
 *
 * @param text 元の `mitigation` 文字列
 * @param ruleId 警告ログ用のルール ID（任意）
 */
export function parseMitigationTiers(
  text: string | undefined,
  ruleId?: string,
): MitigationTiers | undefined {
  if (!text) return undefined;

  // タグの開始位置を全て収集
  const tagRegex = /\[(Foundation|Enterprise|Advanced)\]/gi;
  const matches: { tier: 'foundation' | 'enterprise' | 'advanced'; start: number; end: number }[] = [];
  let m: RegExpExecArray | null;
  while ((m = tagRegex.exec(text)) !== null) {
    matches.push({
      tier: m[1].toLowerCase() as 'foundation' | 'enterprise' | 'advanced',
      start: m.index,
      end: m.index + m[0].length,
    });
  }

  if (matches.length === 0) return undefined;

  // 各タグの本文範囲 = [このタグの end, 次のタグの start)。最後は文字列末尾まで。
  const result: { foundation?: string; enterprise?: string; advanced?: string } = {};
  for (let i = 0; i < matches.length; i++) {
    const cur = matches[i];
    const next = matches[i + 1];
    const body = text.slice(cur.end, next ? next.start : text.length).trim();
    if (body.length === 0) continue;
    if (result[cur.tier] !== undefined) {
      console.warn(
        `[parseMitigationTiers] Duplicate tier "[${cur.tier[0].toUpperCase()}${cur.tier.slice(1)}]"${
          ruleId ? ` in rule "${ruleId}"` : ''
        }; later occurrence overrides earlier.`,
      );
    }
    result[cur.tier] = body;
  }

  // すべてのタグが空本文だった場合は undefined（無効な markup として扱う）
  if (result.foundation === undefined && result.enterprise === undefined && result.advanced === undefined) {
    return undefined;
  }

  return result;
}
