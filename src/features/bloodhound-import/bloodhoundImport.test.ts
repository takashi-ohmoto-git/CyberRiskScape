import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { BUNDLED_BLOODHOUND_QUERIES, isReadOnlyCypher, loadBloodhoundQueries } from './bloodhoundQueries';
import { parseCypherResponse } from './parseCypherResponse';
import { bloodhoundToFindings } from './bloodhoundToFindings';
import { checkBaseUrl, credentialsFromEnv, fetchBloodhoundQueries, signRequest } from './fetchBloodhound';
import { bloodhoundFindingsForThreat } from './matchBloodhound';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';

/** 公式の API 仕様の応答の形（架空のデータ）。 */
const response = (nodes: Record<string, object>) => ({ data: { nodes, edges: [], node_keys: [], edge_keys: [], literals: [] } });

describe('bloodhoundQueries', () => {
  it('同梱の問い合わせを読み込め、canonicalId はすべて脅威ライブラリに実在する', () => {
    expect(BUNDLED_BLOODHOUND_QUERIES.length).toBeGreaterThan(0);
    const known = new Set(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.canonicalId));
    for (const q of BUNDLED_BLOODHOUND_QUERIES) {
      for (const c of q.canonicalIds) expect(known.has(c), `${q.id}: ${c}`).toBe(true);
    }
  });

  it('同梱の問い合わせはすべて読み取りだけ', () => {
    for (const q of BUNDLED_BLOODHOUND_QUERIES) expect(isReadOnlyCypher(q.cypher), q.id).toBe(true);
  });

  it.each([
    'MATCH (n) DETACH DELETE n',
    'MATCH (n) SET n.owned = true RETURN n',
    'CREATE (n:User) RETURN n',
    'MATCH (n) CALL apoc.do.it() RETURN n',
    'RETURN 1',
  ])('書き込み・手続き呼び出しを含む問い合わせは読み込みでエラー：%s', (cypher) => {
    const yaml = `schemaVersion: 1\nqueries:\n  - id: x\n    title: x\n    cypher: "${cypher}"\n    canonicalIds: [a]\n    severity: High\n    subject: directory\n    excludeTierZero: false\n`;
    expect(() => loadBloodhoundQueries(yaml)).toThrow();
  });
});

describe('parseCypherResponse', () => {
  it('API の応答から種類・名前・Tier Zero の印だけを取り出す（SID 等は持たない）', () => {
    const r = parseCypherResponse(
      response({
        'S-1-5-21-1-1104': { label: 'ALICE@CORP.EXAMPLE', kind: 'User', objectId: 'S-1-5-21-1-1104', isTierZero: false, properties: { name: 'ALICE@CORP.EXAMPLE' } },
        'S-1-5-21-1-1000': { label: 'DC01.CORP.EXAMPLE', kinds: ['Computer', 'Base'], isTierZero: true },
      }),
    );
    expect(r).toEqual({
      ok: true,
      nodes: [
        { kind: 'User', name: 'ALICE@CORP.EXAMPLE', isTierZero: false },
        { kind: 'Computer', name: 'DC01.CORP.EXAMPLE', isTierZero: true },
      ],
    });
    expect(JSON.stringify(r)).not.toContain('S-1-5-21');
  });

  it('該当 0 件の HTTP 404（resource not found）は 0 件として読み、他のエラーの本文はエラー', () => {
    const notFound = { http_status: 404, timestamp: 't', request_id: 'r', errors: [{ context: '', message: 'resource not found' }] };
    expect(parseCypherResponse(notFound)).toEqual({ ok: true, nodes: [] });
    const badRequest = { http_status: 400, errors: [{ context: '', message: 'cypher query could not be parsed' }] };
    expect(parseCypherResponse(badRequest).ok).toBe(false);
  });

  it('data を外したグラフだけでも読め、形が違えばエラー', () => {
    expect(parseCypherResponse({ nodes: {} })).toEqual({ ok: true, nodes: [] });
    expect(parseCypherResponse({ data: [] }).ok).toBe(false);
  });
});

describe('bloodhoundToFindings', () => {
  const q = (id: string) => BUNDLED_BLOODHOUND_QUERIES.find((x) => x.id === id)!;
  const dir = { layer: 'L1' as const, nodeId: 'ad' };
  const ca = { layer: 'L1' as const, nodeId: 'ca' };
  const base = { scope: 'corp', importedAt: '2026-11-15T00:00:00Z' };

  it('ユーザーの名前は残さず件数だけ、コンピューター等の資産の名前は残す', () => {
    const { findings } = bloodhoundToFindings({
      ...base,
      queries: [q('laps-readers-non-tier-zero')],
      results: new Map([
        [
          'laps-readers-non-tier-zero',
          [
            { kind: 'User', name: 'ALICE@CORP.EXAMPLE', isTierZero: false },
            { kind: 'Group', name: 'HELPDESK@CORP.EXAMPLE', isTierZero: false },
            { kind: 'Computer', name: 'WS01.CORP.EXAMPLE', isTierZero: false },
          ],
        ],
      ]),
      subjects: { directory: dir },
    });
    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f).toMatchObject({
      id: 'BloodHound CE:corp:laps-readers-non-tier-zero',
      source: { format: 'bloodhound', product: 'BloodHound CE', scope: 'corp' },
      severity: 'High',
      canonicalIds: ['directory-local-admin-password-overread'],
      subject: dir,
    });
    expect(f.title).toContain('3 件');
    expect(f.resource?.label).toContain('HELPDESK@CORP.EXAMPLE');
    expect(f.resource?.label).toContain('WS01.CORP.EXAMPLE');
    expect(f.resource?.label).toContain('ユーザー 1');
    expect(JSON.stringify(findings)).not.toContain('ALICE');
  });

  it('Tier Zero を除く問い合わせは Tier Zero を数えず、0 件なら指摘にしない', () => {
    const { findings, reports } = bloodhoundToFindings({
      ...base,
      queries: [q('dcsync-non-tier-zero')],
      results: new Map([['dcsync-non-tier-zero', [{ kind: 'Group', name: 'DOMAIN ADMINS@CORP.EXAMPLE', isTierZero: true }]]]),
      subjects: { directory: dir },
    });
    expect(findings).toEqual([]);
    expect(reports[0]).toMatchObject({ evaluated: true, count: 0, excludedTierZero: 1 });
  });

  it('AD CS の問い合わせは認証局に、無ければディレクトリに載せる。結果の無い問い合わせは未評価', () => {
    const results = new Map([['adcs-esc-paths', [{ kind: 'Group', name: 'DOMAIN USERS@CORP.EXAMPLE', isTierZero: false }]]]);
    const withCa = bloodhoundToFindings({ ...base, queries: [q('adcs-esc-paths'), q('kerberoastable-users')], results, subjects: { directory: dir, ca } });
    expect(withCa.findings[0].subject).toEqual(ca);
    expect(withCa.reports[1]).toMatchObject({ queryId: 'kerberoastable-users', evaluated: false });
    const noCa = bloodhoundToFindings({ ...base, queries: [q('adcs-esc-paths')], results, subjects: { directory: dir } });
    expect(noCa.findings[0].subject).toEqual(dir);
  });
});

describe('bloodhoundFindingsForThreat', () => {
  it('同じノードで canonicalId が一致する BloodHound の指摘だけを返す', () => {
    const { findings } = bloodhoundToFindings({
      scope: 's',
      importedAt: 't',
      queries: [BUNDLED_BLOODHOUND_QUERIES.find((x) => x.id === 'kerberoastable-users')!],
      results: new Map([['kerberoastable-users', [{ kind: 'User', isTierZero: false }]]]),
      subjects: { directory: { layer: 'L1', nodeId: 'ad' } },
    });
    expect(bloodhoundFindingsForThreat(findings, { nodeId: 'ad', canonicalId: 'directory-offline-credential-cracking' })).toHaveLength(1);
    expect(bloodhoundFindingsForThreat(findings, { nodeId: 'other', canonicalId: 'directory-offline-credential-cracking' })).toEqual([]);
    expect(bloodhoundFindingsForThreat(findings, { nodeId: 'ad', canonicalId: 'directory-delegation-abuse' })).toEqual([]);
    expect(bloodhoundFindingsForThreat(findings, { nodeId: 'ad' })).toEqual([]);
  });
});

describe('fetchBloodhound', () => {
  const creds = { tokenId: 'token-id-1', tokenKey: 'super-secret-key' };

  it('署名は公式の API 仕様の HMAC の連鎖（メソッド＋URI → 日時の時まで → 本文）', async () => {
    const now = new Date('2026-11-15T09:30:45.123Z');
    const body = '{"query":"MATCH (n) RETURN n"}';
    const h = await signRequest(creds, 'POST', '/api/v2/graphs/cypher', body, now);
    const k1 = createHmac('sha256', creds.tokenKey).update('POST/api/v2/graphs/cypher').digest();
    const k2 = createHmac('sha256', k1).update('2026-11-15T09').digest();
    const expected = createHmac('sha256', k2).update(body).digest('base64');
    expect(h).toEqual({ Authorization: 'bhesignature token-id-1', RequestDate: '2026-11-15T09:30:45Z', Signature: expected });
    expect(JSON.stringify(h)).not.toContain(creds.tokenKey);
  });

  it('URL は https（localhost は http 可）。利用者名・クエリを含む URL は拒否', () => {
    expect(checkBaseUrl('https://bh.example.com/')).toBe('https://bh.example.com');
    expect(checkBaseUrl('http://localhost:8080')).toBe('http://localhost:8080');
    expect(() => checkBaseUrl('http://bh.example.com')).toThrow();
    expect(() => checkBaseUrl('https://u:p@bh.example.com')).toThrow();
    expect(() => checkBaseUrl('https://bh.example.com/?x=1')).toThrow();
  });

  it('環境変数が無ければエラー（値は出さない）', () => {
    expect(() => credentialsFromEnv({})).toThrow(/BLOODHOUND_TOKEN_ID/);
    expect(credentialsFromEnv({ BLOODHOUND_TOKEN_ID: ' a ', BLOODHOUND_TOKEN_KEY: 'b' })).toEqual({ tokenId: 'a', tokenKey: 'b' });
  });

  it('同梱の問い合わせだけを cypher の口に POST し、失敗は未評価として返す。エラー文言に鍵を出さない', async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const queries = BUNDLED_BLOODHOUND_QUERIES.slice(0, 2);
    const fakeFetch = (async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      if (calls.length === 2) throw new Error(`boom ${creds.tokenKey}`);
      return new Response(JSON.stringify(response({})), { status: 200 });
    }) as unknown as typeof fetch;
    const r = await fetchBloodhoundQueries('https://bh.example.com', creds, queries, fakeFetch, () => new Date('2026-11-15T00:00:00Z'));
    expect(calls.map((c) => [c.url, c.init.method])).toEqual([
      ['https://bh.example.com/api/v2/graphs/cypher', 'POST'],
      ['https://bh.example.com/api/v2/graphs/cypher', 'POST'],
    ]);
    expect(JSON.parse(calls[0].init.body as string)).toEqual({ query: queries[0].cypher, include_properties: false });
    expect(calls[0].init.redirect).toBe('error');
    expect([...r.responses.keys()]).toEqual([queries[0].id]);
    expect(r.failed).toEqual([{ queryId: queries[1].id, reason: 'boom ***' }]);
  });
});
