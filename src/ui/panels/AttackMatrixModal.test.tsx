import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { AttackMatrixModal } from './AttackMatrixModal';
import type { AttackGraphResult } from '../../features/attack-tree/buildAttackGraph';
import type { AnalyzeGraphResult } from '../../features/attack-tree/analyzeAttackGraph';
import type { ThreatView } from '../../core/model/types';

const graph = { nodeIds: ['A'], hops: new Map(), routes: [], channelCombinations: 0, truncated: false } as AttackGraphResult;
const analysis = { routes: [] } as unknown as AnalyzeGraphResult;
const threat = {
  id: 't1',
  origin: 'detected',
  nodeId: 'n1',
  framework: 'STRIDE',
  category: 'c',
  severity: 'High',
  description: 'd',
  complianceRefs: [{ standard: 'mitre-f3', ref: 'F1002' }],
} as ThreatView;

const render = (framework?: 'f3') =>
  renderToStaticMarkup(
    <AttackMatrixModal
      framework={framework}
      attackerId="A"
      allThreats={[threat]}
      graph={graph}
      analysis={analysis}
      nodes={[]}
      edges={[]}
      onClose={() => {}}
    />,
  );

describe('AttackMatrixModal', () => {
  it('f3: F3 の戦術・テクニックと出典を描き、経路外の該当を数える', () => {
    const html = render('f3');
    expect(html).toContain('Fight Fraud Framework');
    expect(html).toContain('Monetization');
    expect(html).toContain('F1002');
    expect(html).toContain('経路外 1 件');
  });

  it('既定は ATT&CK で F3 の ID を含まない', () => {
    const html = render();
    expect(html).toContain('Enterprise');
    expect(html).not.toContain('Monetization');
  });
});
