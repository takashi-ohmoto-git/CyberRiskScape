import { describe, expect, it } from 'vitest';
import { renderEdgeTemplate, renderNodeTemplate, renderTemplate } from './renderTemplate';
import type { DiagramNode } from '../model/types';

const user: DiagramNode = { id: 'u', type: 'USER', x: 0, y: 0, label: 'エンドユーザー' };
const gateway: DiagramNode = { id: 'g', type: 'GATEWAY', x: 0, y: 0 };
const llm: DiagramNode = { id: 'l', type: 'LLM', x: 0, y: 0, label: '   ' };

describe('renderTemplate', () => {
  it('edge: sourceName / targetName を展開する', () => {
    const out = renderEdgeTemplate('{{sourceName}} → {{targetName}}', user, gateway);
    // label 未指定の gateway は型名（APIゲートウェイ）にフォールバック
    expect(out).toBe('エンドユーザー → APIゲートウェイ');
  });

  it('edge: sourceType / targetType を展開する', () => {
    const out = renderEdgeTemplate('{{sourceType}}/{{targetType}}', user, gateway);
    expect(out).toBe('ユーザー/APIゲートウェイ');
  });

  it('node: nodeName / nodeType を展開する', () => {
    const out = renderNodeTemplate('[{{nodeType}}] {{nodeName}}', user);
    expect(out).toBe('[ユーザー] エンドユーザー');
  });

  it('空白だけの label は型名にフォールバック', () => {
    const out = renderNodeTemplate('{{nodeName}}', llm);
    expect(out).toBe('LLMモデル');
  });

  it('未知トークンは原文のまま残す', () => {
    const out = renderEdgeTemplate('{{unknown}}/{{sourceName}}', user, gateway);
    expect(out).toBe('{{unknown}}/エンドユーザー');
  });

  it('node コンテキストで edge 専用トークンは展開しない', () => {
    const out = renderTemplate('{{sourceName}}', { kind: 'node', node: user });
    expect(out).toBe('{{sourceName}}');
  });

  it('複数回出現するトークンも置換する', () => {
    const out = renderEdgeTemplate('{{sourceName}} と {{sourceName}}', user, gateway);
    expect(out).toBe('エンドユーザー と エンドユーザー');
  });

  it('トークンを含まない文字列はそのまま返す', () => {
    const out = renderEdgeTemplate('plain text', user, gateway);
    expect(out).toBe('plain text');
  });
});
