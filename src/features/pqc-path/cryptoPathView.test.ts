import { describe, expect, it } from 'vitest';
import type { CryptoFlow } from '../../core/model/types';
import { findCryptoFlow, routeNodeRoles, segmentSpans } from './cryptoPathView';
import type { CryptoRoute, CryptoSegment } from './types';
import {
  PQC_VERDICT_BADGE,
  PQC_VERDICT_BAND_BG,
  PQC_VERDICT_BAND_BORDER,
  PQC_VERDICT_ICON,
  PQC_VERDICT_LABEL_KEY,
  PQC_VERDICT_ORDER,
} from '../../ui/panels/pqcVerdictStyle';

const seg = (from: string, to: string): CryptoSegment => ({
  fromNodeId: from,
  toNodeId: to,
  viaNodeIds: [],
  edgeIds: [],
  startTermination: { value: 'endpoint', confidence: 'endpoint' },
  providerManaged: false,
  probability: 'low',
  pqc: 'unknown',
  signatureClass: 'unknown',
  protocols: [],
  kex: [],
  signatures: [],
  warnings: [],
});

const route: CryptoRoute = {
  nodeIds: ['a', 'b', 'c', 'd'],
  edgeIds: ['e1', 'e2', 'e3'],
  segments: [seg('a', 'c'), seg('c', 'd')],
};

describe('cryptoPathView', () => {
  it('ノードの役割（端点・切れ目・経由）を判定する', () => {
    expect(routeNodeRoles(route)).toEqual(['endpoint', 'via', 'cut', 'endpoint']);
  });

  it('区間のノード列上の位置を返す', () => {
    expect(segmentSpans(route)).toEqual([
      { from: 0, to: 2 },
      { from: 2, to: 3 },
    ]);
  });

  it('同じ送信元・送信先の登録済みフローを見つける', () => {
    const flows: CryptoFlow[] = [{ id: 'cf1', sourceId: 'a', targetId: 'd' }];
    expect(findCryptoFlow(flows, 'a', 'd')?.id).toBe('cf1');
    expect(findCryptoFlow(flows, 'd', 'a')).toBeUndefined();
    expect(findCryptoFlow(undefined, 'a', 'd')).toBeUndefined();
  });

  it('PQC 判定のスタイルが全値を網羅する', () => {
    for (const v of PQC_VERDICT_ORDER) {
      expect(PQC_VERDICT_BADGE[v]).toBeTruthy();
      expect(PQC_VERDICT_BAND_BG[v]).toBeTruthy();
      expect(PQC_VERDICT_BAND_BORDER[v]).toBeTruthy();
      expect(PQC_VERDICT_ICON[v]).toBeTruthy();
      expect(PQC_VERDICT_LABEL_KEY[v]).toBeTruthy();
    }
  });
});
