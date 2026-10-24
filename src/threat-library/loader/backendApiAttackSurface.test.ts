import { describe, expect, it } from 'vitest';
import { BUNDLED_THREAT_LIBRARY } from './bundledLibrary';
import { detectThreats } from '../../core/threat-engine/detectThreats';
import type { DiagramNode } from '../../core/model/types';

/** BACKEND_API の攻撃面属性（2026-10-24 追加）。未入力は insecure baseline（Global IP あり・防御策なし）で評価する。 */
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

const detect = (api: DiagramNode) =>
  detectThreats({ nodes: [api], edges: [], framework: 'ALL', rules: BUNDLED_THREAT_LIBRARY.rules });

describe('BACKEND_API の攻撃面属性', () => {
  it('未入力では公開サーバー向けのルールが「未入力のため仮定」付きで出る', () => {
    const out = detect({ id: 'api', type: 'BACKEND_API', x: 0, y: 0 });
    for (const id of STRIDE_WEB_RULES) {
      const hit = out.find((t) => t.ruleId === id);
      expect(hit, id).toBeDefined();
      expect(hit!.assumptionFlags).toContain('attackSurface');
    }
    // ログの取得は攻撃面属性（hasAccessLog）で問うため、posture の log グループのルールは出ない
    expect(out.map((t) => t.ruleId)).not.toContain('posture-log-not-collected-001');
    // 応答キャッシュは前段の性質なので対象外
    expect(out.map((t) => t.ruleId)).not.toContain('netinfra-reverse-proxy-cache-poisoning-001');
  });

  it('Global IP なし・防御策ありと入力すれば出ない', () => {
    const out = detect({
      id: 'api',
      type: 'BACKEND_API',
      x: 0,
      y: 0,
      attackSurface: {
        hasGlobalIp: false,
        hasSourceIpRestriction: true,
        hasRemoteAccessRestriction: true,
        hasUserAuthentication: true,
        hasAccessLog: true,
        hasWafProtection: true,
        hasDdosProtection: true,
      },
    });
    expect(out.filter((t) => STRIDE_WEB_RULES.includes(t.ruleId ?? ''))).toEqual([]);
  });
});
