import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseOcsf } from './parseOcsf';
import { loadOcsfMap, ocsfCanonicalIds, BUNDLED_OCSF_MAP } from './ocsfMap';
import { resourceIdentifiers } from './ocsfToProject';
import { importOcsf, ocsfReportToMarkdown } from '../../cli/importOcsf';
import { reconcileAsm } from '../asm-import/reconcileAsm';
import { deserializeProject } from '../persistence/serialize';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';

/** 架空の OCSF の検査結果（2 製品・Compliance と Detection・対象外のクラス・抑止済み）。 */
const raw = JSON.parse(readFileSync(new URL('./__fixtures__/sample.ocsf.json', import.meta.url), 'utf8')) as unknown;
const PROJECT = new URL('../../cli/__fixtures__/sample-project.json', import.meta.url);
const project = () => JSON.parse(readFileSync(PROJECT, 'utf8')) as unknown;
const AZURE_ID = '/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg-portal/providers/Microsoft.Storage/storageAccounts/portalfiles';

function parsed() {
  const p = parseOcsf(raw);
  if (!p.ok) throw new Error(p.error);
  return p;
}

describe('parseOcsf', () => {
  it('Compliance・Detection を読み、状態・検査 ID・リソースを取り出す。対象外のクラスと抑止済みは数えるだけ', () => {
    const p = parsed();
    expect(p.findings.map((f) => `${f.product} ${f.checkId} ${f.status}`)).toEqual([
      'Example CSPM STORAGE.PUBLIC.1 FAIL',
      'Example CSPM APPSVC.DEPLOY.2 PASS',
      'Prowler s3_bucket_default_encryption FAIL',
    ]);
    expect(p.skipped).toEqual({ invalid: 0, otherClass: 1, closed: 1 });
    expect(p.findings[0].resources[0]).toMatchObject({ uid: AZURE_ID, provider: 'Azure', account: '00000000-1111-2222-3333-444444444444', region: 'japaneast', service: 'storage', nodeTag: 'C2' });
    expect(JSON.stringify(p)).not.toMatch(/SHOULD-NOT-BE-STORED/);
  });

  it('Detection Finding は status_code が無くても FAIL。Compliance の status 文字列だけでも読む', () => {
    const p = parseOcsf([
      { class_uid: 2004, metadata: { product: { name: 'X' } }, finding_info: { uid: 'a', analytic: { uid: 'rule-1' } } },
      { class_uid: 2003, metadata: { product: { name: 'X' } }, finding_info: { uid: 'b' }, compliance: { status: 'Warning', control: 'C-1' } },
    ]);
    if (!p.ok) throw new Error(p.error);
    expect(p.findings.map((f) => `${f.checkId} ${f.status}`)).toEqual(['rule-1 FAIL', 'C-1 MANUAL']);
  });

  it('読める項目が無ければエラー', () => {
    expect(parseOcsf([{ foo: 1 }]).ok).toBe(false);
    expect(parseOcsf('x').ok).toBe(false);
  });
});

describe('ocsfMap', () => {
  it('同梱の対応表を読め、canonicalId は脅威ライブラリに実在する。Prowler は prowler.yaml を使う', () => {
    const known = new Set(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.canonicalId));
    for (const p of BUNDLED_OCSF_MAP) for (const m of p.mappings) for (const id of m.canonicalIds) expect(known.has(id), id).toBe(true);
    expect(ocsfCanonicalIds('Prowler', 's3_bucket_default_encryption', [])).toContain('data-at-rest-unencrypted');
    const map = loadOcsfMap('schemaVersion: 1\nproducts:\n  - product: Example CSPM\n    mappings:\n      - checks: [STORAGE.PUBLIC.1]\n        canonicalIds: [x]\n');
    expect(ocsfCanonicalIds('example cspm', 'STORAGE.PUBLIC.1', map)).toEqual(['x']);
    expect(() => loadOcsfMap('schemaVersion: 1\nproducts:\n  - product: A\n    mappings:\n      - { checks: [c], canonicalIds: [x] }\n      - { checks: [c], canonicalIds: [y] }\n')).toThrow();
  });

  it('リソースの ID の形で同一判定の鍵を変える（ARN・Azure の ID はアカウントを含む完全な形）', () => {
    expect(resourceIdentifiers('arn:aws:s3:::b', 'b')).toEqual([{ scheme: 'arn', value: 'arn:aws:s3:::b' }]);
    expect(resourceIdentifiers('/subscriptions/ABC/x', undefined)).toEqual([{ scheme: 'azure-resource-id', value: '/subscriptions/abc/x' }]);
    expect(resourceIdentifiers(undefined, 'vm-1')).toEqual([{ scheme: 'cloud-resource-id', value: 'vm-1' }]);
  });
});

describe('importOcsf', () => {
  it('FAIL を製品ごとの指摘に、全リソースを資産（kind: resource、完全な ID）にする。対応表に無い検査は脅威と結ばず残す', () => {
    const out = importOcsf(project(), parsed(), { scope: 'acct-1', importedAt: '2026-11-15T00:00:00Z' });
    const findings = out.project.findings ?? [];
    expect(findings.map((f) => `${f.source.product} ${f.canonicalIds.join(',') || '-'}`).sort()).toEqual([
      'Example CSPM -',
      'Prowler data-at-rest-unencrypted',
    ]);
    expect(findings.find((f) => f.source.product === 'Example CSPM')?.subject).toEqual({ layer: 'L1', nodeId: 'n-llm' });
    expect(out.unmappedChecks).toEqual([{ product: 'Example CSPM', checkId: 'STORAGE.PUBLIC.1', count: 1 }]);

    const assets = out.project.assets ?? [];
    expect(assets).toHaveLength(3);
    expect(assets.every((a) => a.kind === 'resource' && a.host === undefined && a.source.format === 'ocsf')).toBe(true);
    const storage = assets.find((a) => a.cloud?.name === 'portalfiles')!;
    expect(storage).toMatchObject({ externalId: `resource:${AZURE_ID}`, subject: { layer: 'L1', nodeId: 'n-llm' } });
    expect(storage.cloud?.account).toBe('00000000-1111-2222-3333-444444444444');
    expect(assets.find((a) => a.cloud?.name === 'example-backup-bucket')?.cloud?.account).toBe('123456789012');
    expect(out.resources).toMatchObject({ total: 3, linked: 1, providers: ['Azure', 'aws'] });
    expect(ocsfReportToMarkdown(out)).toContain('STORAGE.PUBLIC.1');
  });

  it('保存して読み直せる（host の無い resource）。同じ製品 × scope は置き換え、別の scope は残す', () => {
    const first = importOcsf(project(), parsed(), { scope: 'acct-1' });
    const again = importOcsf(first.project, parsed(), { scope: 'acct-1' });
    expect(again.project.assets).toHaveLength(3);
    expect(again.products.find((p) => p.product === 'Prowler')).toMatchObject({ added: 0, continued: 1 });
    const other = importOcsf(first.project, parsed(), { scope: 'acct-2' });
    expect(other.project.assets).toHaveLength(6);
    const reloaded = deserializeProject(JSON.parse(JSON.stringify(other.project)));
    expect(reloaded?.assets?.filter((a) => a.kind === 'resource')).toHaveLength(6);
  });

  it('import-prowler（scope なし）の Prowler の指摘があれば、重複の注意を報告に出す', () => {
    const prowlerFinding = {
      id: 'Prowler:x',
      source: { format: 'ocsf', product: 'Prowler', importedAt: 't' },
      externalId: 'x',
      identifiers: [],
      severity: 'Medium',
      canonicalIds: [],
    };
    const withProwler = { ...(project() as Record<string, unknown>), findings: [prowlerFinding] };
    const out = importOcsf(withProwler, parsed(), { scope: 'acct-1' });
    expect(out.prowlerOverlap).toBe(true);
    expect(ocsfReportToMarkdown(out)).toContain('重複');
    expect(importOcsf(project(), parsed(), { scope: 'acct-1' }).prowlerOverlap).toBe(false);
  });

  it('service・endpoint の資産は host が無いと読み込めない', () => {
    const p = project() as Record<string, unknown>;
    const bad = { ...p, assets: [{ id: 'x', source: { format: 'shodan', product: 'Shodan', importedAt: 't' }, kind: 'service' }] };
    expect(deserializeProject(bad)).toBeNull();
  });

  it('asm-reconcile：図のノードに結びついていないクラウドのリソースを出す', () => {
    const out = importOcsf(project(), parsed(), { scope: 'acct-1' });
    const r = reconcileAsm({ layers: { L1: { nodes: [{ id: 'n-llm' } as never] } }, assets: out.project.assets });
    expect(r.cloudResources?.total).toBe(3);
    expect(r.cloudResources?.unbound.map((u) => u.name).sort()).toEqual(['example-backup-bucket', 'hr-app']);
    expect(r.cloudResources?.unbound.find((u) => u.name === 'hr-app')?.uid).toMatch(/^\/subscriptions\//);
    expect(reconcileAsm({ layers: {}, assets: [] }).cloudResources).toBeUndefined();
  });
});
