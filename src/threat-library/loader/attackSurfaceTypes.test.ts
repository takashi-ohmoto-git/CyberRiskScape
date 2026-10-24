import { describe, expect, it } from 'vitest';
import { BUNDLED_THREAT_LIBRARY } from './bundledLibrary';
import { detectThreats } from '../../core/threat-engine/detectThreats';
import {
  ATTACK_SURFACE_APPLICABLE,
  ATTACK_SURFACE_KEYS_BY_TYPE,
  type AttackSurfaceKey,
  type ComponentTypeId,
  type DiagramNode,
} from '../../core/model/types';

/**
 * 攻撃面属性を条件にするルールの対象型と、型ごとに入力できる項目（ATTACK_SURFACE_KEYS_BY_TYPE）の整合。
 * 入力できない項目を問うと、未入力（悪い値）のまま利用者が消せないカードになるため、対象に入れない。
 */
const accepts = (type: ComponentTypeId, key: string): boolean => {
  if (!ATTACK_SURFACE_APPLICABLE.has(type)) return false;
  const keys: readonly string[] | undefined = ATTACK_SURFACE_KEYS_BY_TYPE[type];
  return !keys || keys.includes(key);
};

const surfaceChecks = BUNDLED_THREAT_LIBRARY.rules.flatMap((rule) => {
  const a = rule.appliesTo;
  if (a.kind !== 'node') return [];
  const targets = a.nodeType ? [a.nodeType] : (a.anyOf ?? []).map((leaf) => leaf.nodeType);
  const checks: { id: string; types: ComponentTypeId[]; keys: string[] }[] = [];
  if (a.attackSurface) checks.push({ id: rule.id, types: targets, keys: Object.keys(a.attackSurface) });
  for (const c of a.conditions ?? []) {
    if (c.when.attackSurface) {
      checks.push({ id: `${rule.id} (conditions)`, types: c.when.nodeType ?? targets, keys: Object.keys(c.when.attackSurface) });
    }
  }
  return checks;
});

describe('攻撃面属性のルールと型の入力項目の整合', () => {
  it.each(surfaceChecks.map((c) => [c.id, c] as const))('%s の対象型はすべて条件の項目を入力できる', (_id, c) => {
    const dead = c.types.filter((t) => !c.keys.every((k) => accepts(t, k)));
    expect(dead).toEqual([]);
  });
});

const STRIDE_WEB_RULES = [
  'stride-web-global-ip-exposure-001',
  'stride-web-no-source-ip-restriction-001',
  'stride-web-remote-mgmt-exposed-001',
  'stride-web-no-user-auth-001',
  'stride-web-no-access-log-001',
  'stride-web-no-waf-001',
  'stride-web-no-ddos-protection-001',
  'stride-web-anonymous-on-public-001',
  'stride-web-blind-perimeter-001',
];

const ruleIdsFor = (type: ComponentTypeId, attackSurface?: DiagramNode['attackSurface']) =>
  detectThreats({
    nodes: [{ id: 'n', type, x: 0, y: 0, ...(attackSurface ? { attackSurface } : {}) }],
    edges: [],
    framework: 'ALL',
    rules: BUNDLED_THREAT_LIBRARY.rules,
  });

/** 型の入力項目をすべて「安全側」で埋めた値。 */
const hardened = (type: ComponentTypeId) =>
  Object.fromEntries(
    (ATTACK_SURFACE_KEYS_BY_TYPE[type] ?? []).map((k: AttackSurfaceKey) => [k, k !== 'hasGlobalIp']),
  );

describe.each([
  // BACKEND_API（2026-10-24）・MCP_SERVER / API_CONTROL_PLANE（2026-10-25）
  ['BACKEND_API', STRIDE_WEB_RULES],
  [
    'MCP_SERVER',
    STRIDE_WEB_RULES.filter(
      (id) => !['stride-web-remote-mgmt-exposed-001', 'stride-web-no-waf-001', 'stride-web-no-ddos-protection-001'].includes(id),
    ),
  ],
  [
    'API_CONTROL_PLANE',
    STRIDE_WEB_RULES.filter((id) => !['stride-web-no-waf-001', 'stride-web-no-ddos-protection-001'].includes(id)),
  ],
] as const)('%s の攻撃面属性', (type, expected) => {
  it('未入力では入力できる項目を問うルールだけが「未入力のため仮定」付きで出る', () => {
    const out = ruleIdsFor(type);
    const hits = out.filter((t) => STRIDE_WEB_RULES.includes(t.ruleId ?? ''));
    expect(hits.map((t) => t.ruleId).sort()).toEqual([...expected].sort());
    for (const t of hits) expect(t.assumptionFlags).toContain('attackSurface');
    // ログの取得は攻撃面属性（hasAccessLog）で問うため、posture の log グループのルールは出ない
    expect(out.map((t) => t.ruleId)).not.toContain('posture-log-not-collected-001');
    expect(out.map((t) => t.ruleId)).not.toContain('netinfra-reverse-proxy-cache-poisoning-001');
  });

  it('Global IP なし・防御策ありと入力すれば出ない', () => {
    const out = ruleIdsFor(type, hardened(type));
    expect(out.filter((t) => STRIDE_WEB_RULES.includes(t.ruleId ?? ''))).toEqual([]);
  });
});
