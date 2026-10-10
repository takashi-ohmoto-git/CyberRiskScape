import { describe, expect, it } from 'vitest';
import { buildPqcReport, toPqcCsv } from './pqcReport';
import { BUNDLED_ALGORITHM_TABLE, BUNDLED_TERMINATION_BEHAVIORS } from '../../crypto-behavior/bundled';
import {
  EMPTY_PROJECT_META,
  type CryptoFlow,
  type DiagramEdge,
  type DiagramNode,
  type EdgeCrypto,
} from '../../core/model/types';
import type { Locale } from '../../i18n';

const ids = ['user', 'cdn', 'waf', 'lb', 'sw', 'web'];
const types = ['USER', 'CDN', 'WAF', 'LOAD_BALANCER', 'L2_SWITCH', 'FRONT_END_SERVER'];
const nodes: DiagramNode[] = ids.map((id, i) => ({ id, type: types[i], x: i * 100, y: 0, seq: i + 1 }));
const edge = (i: number, extra: Partial<DiagramEdge> = {}, crypto?: EdgeCrypto): DiagramEdge => ({
  id: `e${i + 1}`,
  source: ids[i],
  target: ids[i + 1],
  auth: 'None',
  network: 'VPC',
  encryption: 'TLS',
  ...extra,
  ...(crypto ? { crypto } : {}),
});
const edges: DiagramEdge[] = [
  edge(0, { network: 'Internet' }),
  edge(1, {}, { kex: 'X25519MLKEM768' }),
  edge(2),
  edge(3, { encryption: 'Plain' }),
  edge(4, { encryption: 'Plain' }),
];
const flow: CryptoFlow = { id: 'cf1', sourceId: 'user', targetId: 'web' };

const build = (
  cryptoFlows: CryptoFlow[],
  over: { nodes?: DiagramNode[]; edges?: DiagramEdge[]; locale?: Locale } = {},
) =>
  buildPqcReport({
    nodes: over.nodes ?? nodes,
    edges: over.edges ?? edges,
    boundaries: [],
    cryptoFlows,
    behaviors: BUNDLED_TERMINATION_BEHAVIORS,
    algorithms: BUNDLED_ALGORITHM_TABLE,
    projectMeta: { ...EMPTY_PROJECT_META, name: 'P1', systemName: 'Sys' },
    locale: over.locale ?? 'ja',
  });

describe('buildPqcReport', () => {
  it('登録フローの区間を行にする（4 区間・区間 2 は量子耐性あり・最後は平文）', () => {
    const r = build([flow]);
    expect(r.rows).toHaveLength(4);
    expect(r.segmentCount).toBe(4);
    expect(r.rows[1].pqc).toBe('量子耐性あり');
    expect(r.rows[3].pqc).toBe('平文');
    expect(r.rows[3].via).toContain('L2');
    expect(r.rows[3].via).toMatch(/^C5 /);
    expect(r.rows[0].kex).toBe('要確認');
    expect(r.rows[0].from).toMatch(/^C1 /);
  });

  it('フロー名は未設定なら 送信元→送信先', () => {
    expect(build([flow]).rows[0].flow).toMatch(/^C1 .* → C6 /);
    expect(build([{ ...flow, label: 'Web 公開' }]).rows[0].flow).toBe('Web 公開');
  });

  it('経路の無いフローは 1 行で警告が入る', () => {
    const r = build([flow], { edges: edges.slice(0, 2) });
    expect(r.rows).toHaveLength(1);
    expect(r.rows[0].segment).toBe('');
    expect(r.rows[0].warnings).toContain('経路が見つからない');
    expect(r.segmentCount).toBe(0);
  });

  it('無向でしか見つからないとき警告が入る', () => {
    const reversed = edges.map((e) => ({ ...e, source: e.target, target: e.source }));
    const r = build([flow], { edges: reversed });
    expect(r.rows.length).toBeGreaterThan(0);
    expect(r.rows.every((x) => x.warnings.includes('エッジの向きを無視して探索した'))).toBe(true);
  });
});

describe('toPqcCsv', () => {
  it('先頭がバージョン行・メタ情報・注記・表の順', () => {
    const lines = toPqcCsv(build([flow])).split('\r\n');
    expect(lines[0]).toBe('スキーマバージョン,1');
    expect(lines[1]).toBe('kind,cyberriskscape-pqc-report');
    expect(lines).toContain('フロー数,1');
    expect(lines).toContain('区間数,4');
    expect(lines.some((l) => l.includes('簡易版'))).toBe(true);
    expect(lines[9]).toMatch(/^フロー,経路 No,区間 No,/);
    expect(lines).toHaveLength(10 + 4);
  });

  it('カンマ・改行・ダブルクォートを含むラベルをエスケープする', () => {
    const labeled = nodes.map((n) => (n.id === 'sw' ? { ...n, label: 'SW, "A"\nB' } : n));
    const csv = toPqcCsv(build([flow], { nodes: labeled }));
    expect(csv).toContain('"C5 SW, ""A""\nB"');
  });

  it('en の見出し', () => {
    const csv = toPqcCsv(build([flow], { locale: 'en' }));
    expect(csv).toContain('Flow,Route No,Segment No,Segment source,Segment destination');
    expect(csv).toContain('Plaintext');
  });

  it('フローが 0 件でもメタ情報は出る', () => {
    const lines = toPqcCsv(build([])).split('\r\n');
    expect(lines[0]).toBe('スキーマバージョン,1');
    expect(lines).toContain('フロー数,0');
    expect(lines).toContain('区間数,0');
    expect(lines).toHaveLength(10);
  });
});
