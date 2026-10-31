import { describe, expect, it } from 'vitest';
import { MAX_FINDINGS } from '../../core/model/types';
import { readFileSync } from 'node:fs';
import { deserializeProject } from '../persistence/serialize';
import type { ImportNodeRef } from '../findings-import/resolveNode';
import { parseProwlerOcsf, type NormalizedProwlerFinding } from './parseProwlerOcsf';
import { BUNDLED_PROWLER_MAP } from './prowlerMap';
import { toFindings } from './toFindings';

const NODES: ImportNodeRef[] = [
  { id: 'n-bucket', layer: 'L1', seq: 3, type: 'STORAGE' },
  { id: 'n-db', layer: 'L1', seq: 2, type: 'DATABASE' },
];

function f(over: Partial<NormalizedProwlerFinding> = {}): NormalizedProwlerFinding {
  return {
    checkId: 's3_bucket_public_access',
    status: 'FAIL',
    severity: 'Medium',
    title: '公開バケット',
    uid: 'uid-1',
    resources: [{ uid: 'arn:aws:s3:::docs', name: 'docs', type: 'AwsS3Bucket', region: 'ap-northeast-1' }],
    categories: [],
    ...over,
  };
}

const run = (findings: NormalizedProwlerFinding[], nodeMap?: Record<string, string>) =>
  toFindings({ findings, map: BUNDLED_PROWLER_MAP, nodes: NODES, nodeMap, productVersion: '5.0.0', importedAt: '2026-10-31T00:00:00Z' });

describe('toFindings', () => {
  it('FAIL だけを指摘にする（PASS・MANUAL は除外）', () => {
    const out = run([f(), f({ status: 'PASS', uid: 'u2' }), f({ status: 'MANUAL', uid: 'u3' })]);
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0].id).toBe('Prowler:uid-1');
    expect(out.findings[0].source).toEqual({
      format: 'ocsf',
      product: 'Prowler',
      productVersion: '5.0.0',
      importedAt: '2026-10-31T00:00:00Z',
    });
    expect(out.findings[0].identifiers).toEqual([{ scheme: 'prowler-check', value: 's3_bucket_public_access' }]);
  });

  it('uid が無ければ検査 ID と資源から作り、12 桁のアカウント ID は伏せる', () => {
    const out = run([f({ uid: undefined, resources: [{ uid: 'arn:aws:iam::123456789012:user/x' }] })]);
    expect(out.findings[0].externalId).toBe('s3_bucket_public_access:arn:aws:iam::*:user/x');
    expect(out.findings[0].id).not.toContain('123456789012');
    expect(JSON.stringify(out.findings[0])).not.toContain('123456789012');
  });

  it('同じ入力なら同じ ID（安定）', () => {
    expect(run([f()]).findings.map((x) => x.id)).toEqual(run([f()]).findings.map((x) => x.id));
  });

  it('資源が複数ある指摘は資源ごとに 1 件で、ID が重ならない', () => {
    const out = run([f({ resources: [{ uid: 'a', name: 'a' }, { uid: 'b', name: 'b' }] })]);
    expect(out.findings.map((x) => x.id)).toEqual(['Prowler:uid-1#a', 'Prowler:uid-1#b']);
  });

  it('製品側の uid が別の資源の指摘と重なっても捨てず、資源で区別する', () => {
    const out = run([f({ resources: [{ uid: 'a', name: 'a' }] }), f({ resources: [{ uid: 'b', name: 'b' }] })]);
    expect(out.findings.map((x) => x.id)).toEqual(['Prowler:uid-1', 'Prowler:uid-1#b']);
  });

  it('まったく同じ指摘が 2 回あれば 1 件にまとめる', () => {
    expect(run([f(), f()]).findings).toHaveLength(1);
  });

  it('資源が無い指摘は資源・対象なしの 1 件', () => {
    const out = run([f({ resources: [] })]);
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0].resource).toBeUndefined();
    expect(out.findings[0].subject).toBeUndefined();
  });

  it.each([
    ['Critical', 'Critical'],
    ['HIGH', 'High'],
    ['medium', 'Medium'],
    ['Low', 'Low'],
    ['Informational', 'Low'],
    ['Unknown', 'Low'],
    [undefined, 'Low'],
  ])('深刻度 %s → %s', (raw, expected) => {
    const x = run([f({ severity: raw })]).findings[0];
    expect(x.severity).toBe(expected);
    expect(x.sourceSeverity).toBe(raw);
  });

  it('タグ crs-node と --map でノードに結びつく', () => {
    const tagged = run([f({ resources: [{ uid: 'r1', nodeTag: 'n-bucket' }] })]).findings[0];
    expect(tagged.subject).toEqual({ layer: 'L1', nodeId: 'n-bucket' });
    const mapped = run([f({ resources: [{ uid: 'r2', name: 'chat-db' }] })], { 'chat-db': 'C2' }).findings[0];
    expect(mapped.subject).toEqual({ layer: 'L1', nodeId: 'n-db' });
  });

  it('ノードが見つからなければ未結合', () => {
    const out = run([f({ resources: [{ uid: 'r', nodeTag: 'n-missing' }] }), f({ uid: 'u9' })]);
    expect(out.findings.every((x) => x.subject === undefined)).toBe(true);
  });

  it('canonicalIds は対応表から引く（対応が無ければ空）', () => {
    const mapped = run([f()]).findings[0];
    expect(mapped.canonicalIds.length).toBeGreaterThan(0);
    expect(run([f({ checkId: 'some_unknown_check' })]).findings[0].canonicalIds).toEqual([]);
  });

  it('上限を超えた分は保存せず件数を返す', () => {
    const many = Array.from({ length: MAX_FINDINGS + 7 }, (_, i) => f({ uid: `uid-${i}` }));
    const out = run(many);
    expect(out.findings).toHaveLength(MAX_FINDINGS);
    expect(out.truncated).toBe(7);
  });

  it('長い文字列を切り、プロジェクトのスキーマ検証を通る', () => {
    const long = 'x'.repeat(900);
    const out = run([f({ uid: long, title: long, resources: [{ uid: long, name: long, region: long, type: long }] })]);
    expect(out.findings[0].externalId.length).toBeLessThanOrEqual(500);
    const base = JSON.parse(readFileSync(new URL('./__fixtures__/sample-project.json', import.meta.url), 'utf-8'));
    expect(deserializeProject({ ...base, findings: out.findings })?.findings).toHaveLength(1);
  });

  it('OCSF の uid・時刻・バージョンを読む', () => {
    const parsed = parseProwlerOcsf([
      {
        metadata: { event_code: 'c1', product: { name: 'Prowler', version: '5.1.2' } },
        status_code: 'FAIL',
        time_dt: '2026-10-30T01:02:03Z',
        finding_info: { uid: 'prowler-c1-123456789012-r', title: 't' },
        resources: [],
      },
    ]);
    if (!parsed.ok) throw new Error(parsed.error);
    expect(parsed.productVersion).toBe('5.1.2');
    expect(parsed.findings[0].uid).toBe('prowler-c1-*-r');
    expect(parsed.findings[0].observedAt).toBe('2026-10-30T01:02:03Z');
  });
});
