import { describe, expect, it } from 'vitest';
import { resolveHost, type ImportNodeRef } from './resolveNode';

const NODES: ImportNodeRef[] = [
  { id: 'n-a', layer: 'L1', seq: 1, type: 'FRONT_END_SERVER' },
  { id: 'n-b', layer: 'L1', seq: 2, type: 'DATABASE' },
  { id: 'n-c', layer: 'L2', seq: 2, type: 'DATABASE' },
];
const host = { hostnames: ['web01'], fqdns: ['web01.example.internal'], ips: ['192.0.2.10'] };

describe('resolveHost', () => {
  it('--node が --map より優先される', () => {
    const r = resolveHost(NODES, host, { web01: 'n-b' }, 'C1');
    expect(r).toMatchObject({ kind: 'found', node: { id: 'n-a' } });
  });

  it('--map をホスト名 → FQDN → IP の順に引く', () => {
    expect(resolveHost(NODES, host, { '192.0.2.10': 'n-a', 'web01.example.internal': 'n-b' })).toMatchObject({
      node: { id: 'n-b' },
    });
    expect(resolveHost(NODES, host, { '192.0.2.10': 'n-a' })).toMatchObject({ node: { id: 'n-a' } });
  });

  it('対応が無い・ノードが無い・C 番号が曖昧なら未結合', () => {
    expect(resolveHost(NODES, host, {})).toEqual({ kind: 'unlinked', reason: 'none' });
    expect(resolveHost(NODES, host, { web01: 'zzz' })).toEqual({ kind: 'unlinked', reason: 'unknownNode', ref: 'zzz' });
    expect(resolveHost(NODES, host, { web01: 'C2' })).toEqual({ kind: 'unlinked', reason: 'ambiguous', ref: 'C2' });
  });
});
