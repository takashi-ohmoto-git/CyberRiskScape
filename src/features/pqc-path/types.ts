import type { CryptoTermination } from '../../core/model/types';

export type TerminationConfidence = 'confirmed' | 'default' | 'unknown' | 'endpoint';

export interface EffectiveTermination {
  value: CryptoTermination | 'endpoint';
  confidence: TerminationConfidence;
}

export type SegmentProbability = 'high' | 'medium' | 'low';
export type SegmentPqc = 'pqc' | 'transitional' | 'vulnerable' | 'plain' | 'unknown';
export type SegmentSignatureClass = 'pqc' | 'transitional' | 'vulnerable' | 'unknown';
export type SegmentWarning = 'passive-decrypt' | 'inspect-resign' | 'outer-tunnel' | 'mixed-channel';

export interface CryptoSegment {
  fromNodeId: string;
  toNodeId: string;
  viaNodeIds: string[];
  edgeIds: string[];
  /** 区間の始点ノードの判定（送信元なら endpoint）。 */
  startTermination: EffectiveTermination;
  providerManaged: boolean;
  probability: SegmentProbability;
  pqc: SegmentPqc;
  signatureClass: SegmentSignatureClass;
  protocols: string[];
  kex: string[];
  signatures: string[];
  warnings: SegmentWarning[];
}

export interface CryptoRoute {
  nodeIds: string[];
  edgeIds: string[];
  segments: CryptoSegment[];
}

export interface CryptoPathResult {
  routes: CryptoRoute[];
  /** 全経路の区間を (fromNodeId, toNodeId, edgeIds) で重複排除。出現順。 */
  uniqueSegments: CryptoSegment[];
  /** 有向で経路が見つからず、無向でやり直した場合 true。 */
  undirectedFallback: boolean;
  truncated: boolean;
}
