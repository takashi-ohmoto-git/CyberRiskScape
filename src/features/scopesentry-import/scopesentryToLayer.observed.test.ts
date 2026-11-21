import { describe, expect, it } from 'vitest';
import { scopesentryRecordsToLayer } from './scopesentryToLayer';
import { setLocale } from '../../i18n';

const WEB = { host: 'www.example.com', ip: '203.0.113.10', port: '443', type: 'http', url: 'https://www.example.com/', tls: true };
const ID = 'scopesentry-203_0_113_10-443-tcp';

function run(crsObserved?: unknown, base: Record<string, unknown> = WEB) {
  const r = scopesentryRecordsToLayer([crsObserved === undefined ? base : { ...base, crsObserved }]);
  if (!r.ok) throw new Error(r.error);
  return { ...r, node: r.layer.nodes.find((n) => n.id === ID)!, edge: r.layer.edges.find((e) => e.target === ID)! };
}

describe('scopesentryRecordsToLayer crsObserved', () => {
  it('crsObserved が無い → 従来どおり（型・攻撃面・線の暗号は分類と TLS 有無だけ）', () => {
    const { node, edge, summary } = run();
    expect(node.type).toBe('FRONT_END_SERVER');
    expect(node.attackSurface).toEqual({ hasGlobalIp: true });
    expect(edge.crypto).toBeUndefined();
    expect(node.description).not.toContain('観測:');
    expect(summary.unknownObservedTypes).toBe(0);
  });

  it('sourceIpRestriction は false のみ受け付け、true は無視する', () => {
    expect(run({ sourceIpRestriction: false }).node.attackSurface).toEqual({ hasGlobalIp: true, hasSourceIpRestriction: false });
    expect(run({ sourceIpRestriction: true }).node.attackSurface).toEqual({ hasGlobalIp: true });
  });

  it('userAuthentication は true のみ受け付け、false は無視する', () => {
    expect(run({ userAuthentication: true }).node.attackSurface).toEqual({ hasGlobalIp: true, hasUserAuthentication: true });
    expect(run({ userAuthentication: false }).node.attackSurface).toEqual({ hasGlobalIp: true });
  });

  it('未知の componentType は無視して件数を数え、レコードは残す', () => {
    const r = run({ componentType: 'NO_SUCH_TYPE', userAuthentication: true });
    expect(r.node.type).toBe('FRONT_END_SERVER');
    expect(r.summary.unknownObservedTypes).toBe(1);
    expect(r.node.attackSurface).toMatchObject({ hasUserAuthentication: true });
  });

  it('壊れた crsObserved（文字列・配列・tls の型違い）はその項目だけ無視する', () => {
    expect(run('x').node.attackSurface).toEqual({ hasGlobalIp: true });
    expect(run([1]).node.attackSurface).toEqual({ hasGlobalIp: true });
    const r = run({ tls: { version: 13 }, userAuthentication: true });
    expect(r.edge.crypto).toBeUndefined();
    expect(r.node.attackSurface).toMatchObject({ hasUserAuthentication: true });
    expect(run({ tls: { version: 'x'.repeat(21) } }).edge.crypto).toBeUndefined();
  });

  it('componentType は分類より優先し、対象外の型には攻撃面を付けない', () => {
    const r = run({ componentType: 'FIREWALL', sourceIpRestriction: false });
    expect(r.node.type).toBe('FIREWALL');
    expect(r.node.attackSurface).toBeUndefined();
    expect(r.node.description).toContain('観測: 機器の型を指定（FIREWALL）');
  });

  it('型の対象外の項目は落とす（MCP_SERVER に hasWafProtection は付かない）', () => {
    const r = scopesentryRecordsToLayer([{ ...WEB, crsObserved: { componentType: 'MCP_SERVER', userAuthentication: true } }]);
    if (!r.ok) throw new Error(r.error);
    const n = r.layer.nodes.find((x) => x.id === ID)!;
    expect(n.type).toBe('MCP_SERVER');
    expect(n.attackSurface).toEqual({ hasGlobalIp: true, hasUserAuthentication: true });
  });

  it('tls は線に encryption と crypto を入れ、kex は観測したときだけ入れる', () => {
    const plain = { ...WEB, tls: undefined, url: undefined };
    const a = run({ tls: { version: '1.3' } }, plain);
    expect(a.edge.encryption).toBe('TLS');
    expect(a.edge.crypto).toEqual({ protocol: 'TLS', version: '1.3' });
    const b = run({ tls: { version: '1.3', kex: 'X25519MLKEM768' } });
    expect(b.edge.crypto).toEqual({ protocol: 'TLS', version: '1.3', kex: 'X25519MLKEM768' });
  });

  it('観測の注記を説明欄に 1 事実 1 行で足す（日本語・英語）', () => {
    const obs = { sourceIpRestriction: false, userAuthentication: true, tls: { version: '1.3', kex: 'X25519MLKEM768' } };
    const ja = run(obs).node.description!;
    expect(ja).toContain('観測: 診断元から到達できた（送信元 IP 制限なし）');
    expect(ja).toContain('観測: 認証の入口あり');
    expect(ja).toContain('観測: TLS 1.3・鍵交換 X25519MLKEM768');
    setLocale('en');
    try {
      expect(run(obs).node.description).toContain('Observed: TLS 1.3, key exchange X25519MLKEM768');
    } finally {
      setLocale('ja');
    }
  });
});
