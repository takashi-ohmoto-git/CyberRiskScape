import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { importProwler, prowlerReportToJson, prowlerReportToMarkdown } from './importProwler';
import { analyzeProject } from './analyze';
import { parseProwlerOcsf } from '../features/prowler-import/parseProwlerOcsf';
import { PersistedProjectSchema } from '../features/persistence/schema';

const read = (name: string) =>
  JSON.parse(readFileSync(new URL(`../features/prowler-import/__fixtures__/${name}`, import.meta.url), 'utf-8'));

const project = read('sample-project.json');
const ocsf = read('sample.ocsf.json');
const nodeMap = read('sample-map.json') as Record<string, string>;

function run(map: Record<string, string> = nodeMap, raw: unknown = project) {
  const parsed = parseProwlerOcsf(ocsf);
  if (!parsed.ok) throw new Error(parsed.error);
  return importProwler(raw, parsed, map);
}

const nodeOf = (p: ReturnType<typeof run>['project'], id: string) => p.layers?.L1?.nodes.find((n) => n.id === id);

describe('importProwler', () => {
  it('未入力の項目だけ埋める（資源内は最良・ノード内は最悪）', () => {
    const out = run();
    expect(nodeOf(out.project, 'n-bucket')?.posture).toEqual({
      encryptionAtRest: 'ProviderManagedKey',
      logCollection: 'NotCollected',
    });
    // chat-db-1 は PASS（ProviderManagedKey）、chat-db-2 は FAIL（None）→ 最も悪い None
    expect(nodeOf(out.project, 'n-db')?.posture).toEqual({ encryptionAtRest: 'None', accountReview: 'Irregular' });
    const web = nodeOf(out.project, 'n-web');
    expect(web?.attackSurface).toEqual({ hasGlobalIp: true, hasAccessLog: true });
    expect(web?.posture).toEqual({ logRetention: 'OneYearOrMore', patchStatus: 'UpToDate' });
  });

  it('入力済みの値と違えば上書きせず食い違いとして報告する', () => {
    const out = run();
    expect(nodeOf(out.project, 'n-legacy')?.posture).toEqual({ encryptionAtRest: 'None' });
    expect(out.result.conflicts).toHaveLength(1);
    expect(out.result.conflicts[0]).toMatchObject({
      nodeId: 'n-legacy',
      field: 'encryptionAtRest',
      current: 'None',
      prowler: 'ProviderManagedKey',
    });
    expect(out.result.conflicts[0].basis[0].checks[0].checkId).toBe('s3_bucket_default_encryption');
  });

  it('同じ値なら何もしない', () => {
    const pre = structuredClone(project);
    pre.layers.L1.nodes[2].posture = { encryptionAtRest: 'ProviderManagedKey' };
    const out = run(nodeMap, pre);
    expect(out.result.unchanged.map((u) => u.field)).toContain('encryptionAtRest');
    expect(out.result.applied.some((a) => a.nodeId === 'n-bucket' && a.field === 'encryptionAtRest')).toBe(false);
  });

  it('型が持たない項目は適用せず報告し、ノードに値を入れない', () => {
    const out = run();
    expect(out.result.notApplicable).toHaveLength(1);
    expect(out.result.notApplicable[0]).toMatchObject({ nodeId: 'n-tool', field: 'encryptionAtRest', type: 'TOOL' });
    expect(nodeOf(out.project, 'n-tool')?.posture).toBeUndefined();
  });

  it('対応のない資源・存在しないノード ID・曖昧でない C 番号を扱う', () => {
    const out = run();
    const byName = Object.fromEntries(out.result.unmatchedResources.map((u) => [u.resource, u]));
    expect(byName['vol-0aaa'].reason).toBe('none');
    expect(byName['ghost-bucket']).toMatchObject({ reason: 'unknownNode', ref: 'n-missing' });
    // タグ crs-node=C5 は C 番号で n-legacy に対応する（unmatched に出ない）
    expect(byName['legacy-bucket']).toBeUndefined();
    // --map が無いと chat-db-1/2 は対応なし
    const noMap = run({});
    expect(noMap.result.unmatchedResources.map((u) => u.resource)).toEqual(
      expect.arrayContaining(['chat-db-1', 'chat-db-2']),
    );
    expect(nodeOf(noMap.project, 'n-db')?.posture).toEqual({ accountReview: 'Irregular' });
  });

  it('FAIL の検査の canonicalId を検出脅威と突き合わせる', () => {
    const out = run();
    const confirmed = out.result.confirmed.map((c) => c.canonicalId);
    expect(confirmed).toEqual(expect.arrayContaining(['log-not-collected', 'web-global-ip-exposure']));
    expect(out.result.notInModel.map((n) => n.canonicalId)).toContain('nhi-long-lived-secret');
    expect(out.result.unmappedChecks.map((u) => u.checkId)).toEqual(['some_unknown_check']);
    // PASS の検査は突き合わせに出ない
    expect(JSON.stringify(out.result.confirmed)).not.toContain('elbv2_logging_enabled');
  });

  it('出力のプロジェクトはスキーマに通り、analyzeProject で解析できる', () => {
    const out = run();
    expect(PersistedProjectSchema.safeParse(out.project).success).toBe(true);
    expect(() => analyzeProject(JSON.parse(JSON.stringify(out.project)))).not.toThrow();
  });

  it('PASS で「未入力のため仮定」の印が消え、FAIL では脅威が出続ける', () => {
    const flags = (raw: unknown, canonicalId: string, nodeId: string) => {
      const results = analyzeProject(raw);
      return results
        .flatMap((r) => r.threats)
        .filter((t) => t.canonicalId === canonicalId && t.subject?.kind === 'node' && t.subject.id === nodeId);
    };
    const filled = JSON.parse(JSON.stringify(run().project));

    // 保管時の暗号化：db は FAIL（None）→ 脅威は出続けるが、仮定ではなくなる
    const dbBefore = flags(project, 'data-at-rest-unencrypted', 'n-db');
    const dbAfter = flags(filled, 'data-at-rest-unencrypted', 'n-db');
    expect(dbBefore.length).toBeGreaterThan(0);
    expect(dbAfter.length).toBeGreaterThan(0);
    expect(dbBefore.some((t) => t.assumptionFlags?.includes('posture'))).toBe(true);
    expect(dbAfter.some((t) => t.assumptionFlags?.includes('posture'))).toBe(false);

    // ログ：bucket は FAIL（NotCollected）→ 脅威は出続ける
    const logAfter = flags(filled, 'log-not-collected', 'n-bucket');
    expect(logAfter.length).toBeGreaterThan(0);
    expect(logAfter.some((t) => t.assumptionFlags?.includes('posture'))).toBe(false);
  });

  it('捨てた値（アカウント ID・資源の data）が報告とプロジェクトに含まれない', () => {
    const out = run();
    const texts = [
      prowlerReportToMarkdown(out),
      JSON.stringify(prowlerReportToJson(out)),
      JSON.stringify(out.project),
    ];
    for (const t of texts) {
      expect(t).not.toContain('123456789012');
      expect(t).not.toContain('SECRET_RESOURCE_DATA_PAYLOAD');
      expect(t).not.toContain('RISKDETAILS_LONG_TEXT');
      expect(t).not.toContain('sample-account');
    }
  });

  it('同じ入力なら出力も同じ（updatedAt 以外）', () => {
    const a = run().project;
    const b = run().project;
    expect({ ...a, updatedAt: 0 }).toEqual({ ...b, updatedAt: 0 });
  });

  it('報告 md に主要な節が出る', () => {
    const md = prowlerReportToMarkdown(run());
    for (const h of ['## 適用した値', '## 食い違い', '## 適用できない', '## 対応するノードが無い資源', '### 確認された']) {
      expect(md).toContain(h);
    }
  });
});
