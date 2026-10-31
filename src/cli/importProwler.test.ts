import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { collectThreatRefs, importProwler, prowlerReportToJson, prowlerReportToMarkdown } from './importProwler';
import { analyzeProject, analyzeResolvedProject, resolveProject } from './analyze';
import { parseProwlerOcsf } from '../features/prowler-import/parseProwlerOcsf';
import { applyProwler } from '../features/prowler-import/applyProwler';
import { BUNDLED_PROWLER_MAP } from '../features/prowler-import/prowlerMap';
import { PersistedProjectSchema } from '../features/persistence/schema';

const read = (name: string) =>
  JSON.parse(readFileSync(new URL(`../features/prowler-import/__fixtures__/${name}`, import.meta.url), 'utf-8'));

const project = read('sample-project.json');
const ocsf = read('sample.ocsf.json');
const nodeMap = read('sample-map.json') as Record<string, string>;

function run(map: Record<string, string> = nodeMap, raw: unknown = project) {
  const parsed = parseProwlerOcsf(ocsf);
  if (!parsed.ok) throw new Error(parsed.error);
  return importProwler(raw, parsed, map, undefined, '2026-10-31T00:00:00.000Z');
}

const nodeOf = (p: ReturnType<typeof run>['project'], id: string) => p.layers?.L1?.nodes.find((n) => n.id === id);

describe('importProwler', () => {
  it('FAIL の指摘を project.findings に保存し、取り込み直しで置き換える', () => {
    const out = run();
    const fs = out.project.findings ?? [];
    expect(fs.length).toBeGreaterThan(0);
    expect(fs.every((f) => f.source.product === 'Prowler')).toBe(true);
    expect(out.findings).toMatchObject({ stored: fs.length, truncated: 0, added: fs.length, resolved: 0, continued: 0 });
    expect(fs.find((f) => f.identifiers[0].value === 's3_bucket_public_access')?.subject).toEqual({
      layer: 'L1',
      nodeId: 'n-bucket',
    });
    expect(JSON.stringify(fs)).not.toContain('123456789012');
    expect(prowlerReportToMarkdown(out)).toContain('## 保存した指摘（FAIL）');
    expect(prowlerReportToJson(out).findings).toEqual(out.findings);

    const again = run(nodeMap, JSON.parse(JSON.stringify(out.project)));
    expect(again.project.findings).toHaveLength(fs.length);
    expect(again.findings).toMatchObject({ added: 0, resolved: 0, continued: fs.length });
  });

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

  it('突き合わせはノード自身の脅威とだけ行い、ノードに結びつかない FAIL は確認済み・図に無いに数えない', () => {
    const out = run();
    // エッジの脅威は突き合わせ対象に渡さない（nodeIds はノード 1 件）
    const refs = collectThreatRefs(analyzeResolvedProject(resolveProject(project)));
    expect(refs.length).toBeGreaterThan(0);
    expect(refs.every((t) => t.nodeIds.length === 1)).toBe(true);
    // 結びつかない資源（vol-0aaa・ghost-bucket）の FAIL は unlinkedFails にだけ出る
    const unlinked = out.result.unlinkedFails.find((u) => u.canonicalId === 'data-at-rest-unencrypted');
    expect(unlinked?.hits.map((h) => h.resource).sort()).toEqual(['ghost-bucket', 'vol-0aaa']);
    expect(out.result.summary.unlinkedFails).toBe(
      out.result.unlinkedFails.reduce((n, u) => n + u.hits.length, 0),
    );
    const bound = JSON.stringify([out.result.confirmed, out.result.notInModel]);
    expect(bound).not.toContain('vol-0aaa');
    expect(bound).not.toContain('ghost-bucket');
    // 結びついたノードの FAIL（n-db の rds 暗号化）は確認済みに入る
    expect(out.result.confirmed.map((c) => c.canonicalId)).toContain('data-at-rest-unencrypted');
    expect(prowlerReportToMarkdown(out)).toContain('### ノードに結びつかないため突き合わせていない');
  });

  it('鍵の種類が未確認の ProviderManagedKey は適用して確認を促し、入力済みの CMK とは食い違いにしない', () => {
    const out = run();
    const a = out.result.applied.find((x) => x.nodeId === 'n-bucket' && x.field === 'encryptionAtRest');
    expect(a).toMatchObject({ value: 'ProviderManagedKey', keyTypeUnverified: true });
    // 最悪の値が None（FAIL）なら確認の対象にしない
    const db = out.result.applied.find((x) => x.nodeId === 'n-db' && x.field === 'encryptionAtRest');
    expect(db?.keyTypeUnverified).toBeUndefined();
    const md = prowlerReportToMarkdown(out);
    expect(md).toContain('## 鍵の種類を確認してください');
    expect(md).toMatch(/鍵の種類を確認してください[\s\S]*文書ストレージ の encryptionAtRest = ProviderManagedKey/);

    // 入力済みが CMK → 食い違いにせず同じ値の扱い（上書きもしない）
    const pre = structuredClone(project);
    pre.layers.L1.nodes[2].posture = { encryptionAtRest: 'CustomerManagedKey' };
    const out2 = run(nodeMap, pre);
    expect(out2.result.conflicts.some((c) => c.nodeId === 'n-bucket')).toBe(false);
    expect(out2.result.unchanged.some((u) => u.nodeId === 'n-bucket' && u.value === 'CustomerManagedKey')).toBe(true);
    expect(nodeOf(out2.project, 'n-bucket')?.posture?.encryptionAtRest).toBe('CustomerManagedKey');

    // 入力済みが None → 従来どおり食い違い
    const pre3 = structuredClone(project);
    pre3.layers.L1.nodes[2].posture = { encryptionAtRest: 'None' };
    expect(run(nodeMap, pre3).result.conflicts.some((c) => c.nodeId === 'n-bucket')).toBe(true);
  });

  it('資源内で CMK を判別できる検査が PASS なら CustomerManagedKey が優先され、確認の対象にならない', () => {
    const f = (checkId: string) => ({
      checkId,
      status: 'PASS' as const,
      resources: [{ uid: 'arn:x', name: 'x', nodeTag: 'n-bucket' }],
      categories: [],
    });
    const nodes = [{ id: 'n-bucket', layer: 'L1' as const, type: 'STORAGE' as const }];
    const r = applyProwler({
      nodes,
      findings: [f('s3_bucket_default_encryption'), f('bedrock_custom_model_encrypted_with_cmk')],
      map: BUNDLED_PROWLER_MAP,
      threats: [],
    });
    expect(r.applied[0]).toMatchObject({ value: 'CustomerManagedKey' });
    expect(r.applied[0].keyTypeUnverified).toBeUndefined();
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
    for (const h of ['## 適用した値', '## 食い違い', '## 適用できない', '## 対応するノードが無い資源', '## 鍵の種類を確認してください', '### 確認された']) {
      expect(md).toContain(h);
    }
  });
});
