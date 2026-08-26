import { describe, expect, it } from 'vitest';
import type { DiagramBoundary, DiagramEdge, DiagramNode } from '../model/types';
import { isHighRiskEdge } from './edgeNotation';
import {
  presentBoundaryTypes,
  presentComponentTypes,
  presentEdgeNotations,
} from './legend';

function edge(partial: Partial<DiagramEdge>): DiagramEdge {
  return {
    id: partial.id ?? 'e1',
    source: 's',
    target: 't',
    auth: 'MFA',
    network: 'VPC',
    encryption: 'TLS',
    ...partial,
  };
}

describe('isHighRiskEdge', () => {
  it('未認証 × Internet のときだけ true', () => {
    expect(isHighRiskEdge({ auth: 'None', network: 'Internet' })).toBe(true);
    expect(isHighRiskEdge({ auth: 'Password', network: 'Internet' })).toBe(false);
    expect(isHighRiskEdge({ auth: 'None', network: 'VPN' })).toBe(false);
  });
});

describe('presentEdgeNotations', () => {
  it('使われている線記法だけを宣言順で返す', () => {
    const result = presentEdgeNotations([
      edge({ encryption: 'Plain' }),
      edge({ encryption: 'TLS' }),
    ]);
    expect(result.map((e) => e.id)).toEqual(['plain', 'encrypted']);
  });

  it('暗号化エッジのみなら平文・高リスクは出さない', () => {
    const result = presentEdgeNotations([edge({ encryption: 'E2EE' })]);
    expect(result.map((e) => e.id)).toEqual(['encrypted']);
  });

  it('高リスク経路を検出する', () => {
    const result = presentEdgeNotations([
      edge({ encryption: 'TLS', auth: 'None', network: 'Internet' }),
    ]);
    expect(result.map((e) => e.id)).toContain('high-risk');
  });

  it('エッジが無ければ空', () => {
    expect(presentEdgeNotations([])).toEqual([]);
  });
});

describe('presentComponentTypes', () => {
  it('重複を除いて初出順で返す', () => {
    const nodes = [
      { type: 'LLM' },
      { type: 'USER' },
      { type: 'LLM' },
    ] as DiagramNode[];
    expect(presentComponentTypes(nodes)).toEqual(['LLM', 'USER']);
  });

  it('ノードが無ければ空', () => {
    expect(presentComponentTypes([])).toEqual([]);
  });
});

describe('presentBoundaryTypes', () => {
  it('重複を除いて初出順で返す', () => {
    const boundaries = [
      { type: 'RECT' },
      { type: 'ROUNDED' },
      { type: 'RECT' },
    ] as DiagramBoundary[];
    expect(presentBoundaryTypes(boundaries)).toEqual(['RECT', 'ROUNDED']);
  });
});
