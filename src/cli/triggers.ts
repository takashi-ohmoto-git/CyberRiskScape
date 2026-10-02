import type { ChangeTrigger } from '../change-triggers/schema/trigger';
import { getLocale, translate } from '../i18n';

/**
 * CLI `triggers` サブコマンド：実行トリガー（T1〜T8 等）をチェックリストとして出す
 * （[[plan]] §2.51）。PR テンプレートや AI レビュアーの観点表にそのまま使える形。
 *
 * `diff.ts` の md/json 変換と同じ設計（`getLocale()` を読む純粋関数、CLI 側で
 * `setLocale` 済みであることを前提にする）。
 */

/** `detect` が空のトリガー（例：T4）はモデル差分から自動判定できない。 */
function isAutoDetected(trigger: ChangeTrigger): boolean {
  return trigger.detect.length > 0;
}

/**
 * PR コメント／PR テンプレートにそのまま貼れる Markdown チェックリストへ変換する純粋関数。
 * 自動判定できる項目とできない項目（人／AI レビューが必要）を節で分ける。
 */
export function triggersToMarkdown(triggers: readonly ChangeTrigger[]): string {
  const locale = getLocale();
  const out: string[] = [];

  out.push(translate('cliTriggers.heading', locale), '', translate('cliTriggers.intro', locale));

  const auto = triggers.filter(isAutoDetected);
  const manual = triggers.filter((t) => !isAutoDetected(t));

  if (auto.length > 0) {
    out.push('', translate('cliTriggers.section.auto', locale), '');
    for (const t of auto) {
      out.push(`- [ ] **${t.id} ${t.title}** — ${t.checkpoint}`);
    }
  }

  if (manual.length > 0) {
    out.push('', translate('cliTriggers.section.manual', locale), '');
    for (const t of manual) {
      out.push(`- [ ] **${t.id} ${t.title}** — ${t.checkpoint}`);
    }
  }

  return out.join('\n');
}

/** 機械処理用の JSON オブジェクトを組み立てる（`toJson` が文字列化する前の形）。 */
export function triggersToJsonObject(triggers: readonly ChangeTrigger[]): Record<string, unknown> {
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-change-triggers',
    triggers: triggers.map((t) => ({
      id: t.id,
      title: t.title,
      checkpoint: t.checkpoint,
      autoDetected: isAutoDetected(t),
    })),
  };
}

/** `triggersToJsonObject` を整形済み JSON 文字列へ変換する。 */
export function triggersToJson(triggers: readonly ChangeTrigger[]): string {
  return JSON.stringify(triggersToJsonObject(triggers), null, 2);
}
