import { describe, expect, it } from 'vitest';
import { BUNDLED_THREAT_LIBRARY } from './bundledLibrary';
import { componentRegistry } from '../../component-library/defaultRegistry';
import type { PostureEnumKey } from '../../core/model/types';

/**
 * 運用状況（posture）を条件にするルールの対象型と、コンポーネント YAML の `posture:` 宣言の整合。
 *
 * ルールのスキーマには「この項目を入力できる全型」を表す指定が無く、対象型を列挙している。
 * 型の宣言を変えたときに列挙がずれないよう、次の 2 点を検査する。
 * - 対象型はすべて、条件にした項目を入力できる（入力できない型を対象にしても発火しない＝死んだ対象）
 * - 条件にした項目をすべて入力できる型は、すべて対象に含まれる（入力しても効かない型を作らない）
 */

/** 一部の型だけを意図して対象にするルール（全型の網羅は検査しない）。 */
const PARTIAL_TARGET_RULES = new Set([
  // 公開サーバー・API ゲートウェイのアクセスログ（attackSurface.hasAccessLog）の保持期間。他の型は -001 が扱う。
  'posture-log-retention-short-002',
  // IdP 固有の認証イベントの記録。ログ取得の宣言で出なくなる。他の型は posture-log-not-collected-001 が扱う。
  'identity-idp-authentication-log-gap-001',
]);

const postureRules = BUNDLED_THREAT_LIBRARY.rules.flatMap((rule) => {
  const a = rule.appliesTo;
  if (a.kind !== 'node' || !a.posture) return [];
  const targets = a.nodeType ? [a.nodeType] : (a.anyOf ?? []).map((leaf) => leaf.nodeType);
  const fields = Object.keys(a.posture) as PostureEnumKey[];
  return [{ id: rule.id, targets, fields }];
});

describe('運用状況のルールと型の posture 宣言の整合', () => {
  it('posture を条件にするルールがある', () => {
    expect(postureRules.length).toBeGreaterThan(0);
  });

  it.each(postureRules.map((r) => [r.id, r] as const))('%s の対象型はすべて条件の項目を入力できる', (_id, r) => {
    const dead = r.targets.filter((t) => !r.fields.every((f) => componentRegistry.acceptsPostureField(t, f)));
    expect(dead).toEqual([]);
  });

  it.each(postureRules.filter((r) => !PARTIAL_TARGET_RULES.has(r.id)).map((r) => [r.id, r] as const))(
    '%s は条件の項目を入力できる型をすべて対象にしている',
    (_id, r) => {
      const accepting = componentRegistry
        .getAll()
        .map((c) => c.id)
        .filter((t) => r.fields.every((f) => componentRegistry.acceptsPostureField(t, f)));
      const missing = accepting.filter((t) => !r.targets.includes(t));
      expect(missing).toEqual([]);
    },
  );
});
