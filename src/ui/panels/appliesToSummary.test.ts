import { describe, expect, it } from 'vitest';
import { summarizeAppliesTo } from './appliesToSummary';
import type { AppliesTo } from '../../threat-library/schema/threatRule';

describe('summarizeAppliesTo - kind: node', () => {
  it('nodeType 単一（connection 省略＝デフォルト文言）', () => {
    const appliesTo: AppliesTo = { kind: 'node', nodeType: 'LLM' };
    const text = summarizeAppliesTo(appliesTo, 'ja');
    expect(text).toContain('LLM');
    expect(text).toContain('何らかの接続があるとき');
  });

  it('anyOf（2件以上の OR 文言）', () => {
    const appliesTo: AppliesTo = {
      kind: 'node',
      anyOf: [{ nodeType: 'AGENT' }, { nodeType: 'LLM' }],
    };
    const text = summarizeAppliesTo(appliesTo, 'ja');
    expect(text).toContain('AIエージェント');
    expect(text).toContain('LLMモデル');
    expect(text).toContain('または');
  });

  // docs/threat-schema.md §3.1 の例 (A)〜(E)
  it('(A) connection 省略時のデフォルト', () => {
    const appliesTo: AppliesTo = { kind: 'node', nodeType: 'AGENT' };
    expect(summarizeAppliesTo(appliesTo, 'ja')).toContain('何らかの接続があるとき');
  });

  it('(B) required:false（内在的脅威）', () => {
    const appliesTo: AppliesTo = {
      kind: 'node',
      nodeType: 'LLM',
      connection: { required: false },
    };
    expect(summarizeAppliesTo(appliesTo, 'ja')).toContain('内在的脅威');
  });

  it('(C) direction: inbound', () => {
    const appliesTo: AppliesTo = {
      kind: 'node',
      nodeType: 'LLM',
      connection: { direction: 'inbound' },
    };
    expect(summarizeAppliesTo(appliesTo, 'ja')).toContain('入力方向');
  });

  it('(D) peerType 指定', () => {
    const appliesTo: AppliesTo = {
      kind: 'node',
      nodeType: 'LLM',
      connection: { direction: 'inbound', peerType: ['USER', 'EXTERNAL_ENTITY'] },
    };
    const text = summarizeAppliesTo(appliesTo, 'ja');
    expect(text).toContain('入力方向');
    expect(text).toContain('ユーザー');
    expect(text).toContain('外部主体');
  });

  it('(E) peerAttackSurface 指定', () => {
    const appliesTo: AppliesTo = {
      kind: 'node',
      nodeType: 'AGENT',
      connection: {
        direction: 'outbound',
        peerType: ['GATEWAY'],
        peerAttackSurface: { hasGlobalIp: true },
      },
    };
    const text = summarizeAppliesTo(appliesTo, 'ja');
    expect(text).toContain('出力方向');
    expect(text).toContain('APIゲートウェイ');
    expect(text).toContain('グローバルIP=true');
  });

  it('attackSurface（対象ノード自身の攻撃面条件）', () => {
    const appliesTo: AppliesTo = {
      kind: 'node',
      nodeType: 'FRONT_END_SERVER',
      attackSurface: { hasGlobalIp: true, hasWafProtection: false },
    };
    const text = summarizeAppliesTo(appliesTo, 'ja');
    expect(text).toContain('グローバルIP=true');
    expect(text).toContain('WAF保護=false');
  });

  it('agentAttributes: agency 単体', () => {
    const appliesTo: AppliesTo = {
      kind: 'node',
      nodeType: 'AGENT',
      connection: { required: false },
      agentAttributes: { agency: ['Autonomous'] },
    };
    const text = summarizeAppliesTo(appliesTo, 'ja');
    expect(text).toContain('自律度=Autonomous');
  });

  it('agentAttributes: 複数フィールド AND・配列内 OR が読み取れる', () => {
    const appliesTo: AppliesTo = {
      kind: 'node',
      nodeType: 'AGENT',
      connection: { required: false },
      agentAttributes: { agency: ['Autonomous', 'Bounded'], identityTier: ['LabelOnly'] },
    };
    const text = summarizeAppliesTo(appliesTo, 'ja');
    expect(text).toContain('自律度=Autonomous/Bounded');
    expect(text).toContain('アイデンティティ強度=LabelOnly');
  });
});

describe('summarizeAppliesTo - kind: edge', () => {
  it('when 単体', () => {
    const appliesTo: AppliesTo = {
      kind: 'edge',
      when: { auth: ['None'], network: ['Internet'] },
    };
    const text = summarizeAppliesTo(appliesTo, 'ja');
    expect(text).toContain('認証=None');
    expect(text).toContain('ネットワーク=Internet');
  });

  it('allOf', () => {
    const appliesTo: AppliesTo = {
      kind: 'edge',
      allOf: [{ sourceType: ['AGENT'] }, { encryption: ['Plain'], auth: ['None'] }],
    };
    const text = summarizeAppliesTo(appliesTo, 'ja');
    expect(text).toContain('送信元=AIエージェント');
    expect(text).toContain('暗号化=Plain');
    expect(text).toContain('認証=None');
    expect(text).toContain('かつ');
  });

  it('anyOf', () => {
    const appliesTo: AppliesTo = {
      kind: 'edge',
      anyOf: [{ targetType: ['LLM'], network: ['Internet'] }, { encryption: ['Plain'] }],
    };
    const text = summarizeAppliesTo(appliesTo, 'ja');
    expect(text).toContain('宛先=LLM');
    expect(text).toContain('暗号化=Plain');
    expect(text).toContain('または');
  });

  it('field ラベル解決: network / encryption 単体でも日本語ラベルに置換される', () => {
    const appliesTo: AppliesTo = {
      kind: 'edge',
      when: { network: ['VPN'] },
    };
    expect(summarizeAppliesTo(appliesTo, 'ja')).toContain('ネットワーク=VPN');

    const encAppliesTo: AppliesTo = {
      kind: 'edge',
      when: { encryption: ['TLS'] },
    };
    expect(summarizeAppliesTo(encAppliesTo, 'ja')).toContain('暗号化=TLS');
  });
});
