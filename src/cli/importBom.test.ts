import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { bomReportToJson, bomReportToMarkdown, importBom } from './importBom';
import { MAX_BOM_COMPONENTS } from '../core/model/types';
import { parseBom, type ParsedBomItem } from '../features/bom-import/parseBom';
import { deserializeProject } from '../features/persistence/serialize';

const AT = '2026-11-05T00:00:00.000Z';
const project = () =>
  JSON.parse(readFileSync(new URL('../features/pentest-import/__fixtures__/sample-project.json', import.meta.url), 'utf-8'));
const roundTrip = (p: unknown) => JSON.parse(JSON.stringify(p));

const item = (externalId: string, kind: ParsedBomItem['kind'] = 'software'): ParsedBomItem => ({
  externalId,
  identifiers: [],
  kind,
  name: externalId,
});
const bom = (items: ParsedBomItem[], format: 'cyclonedx' | 'spdx' = 'cyclonedx') =>
  ({ ok: true, format, specVersion: '1.7', product: 'example', items }) as const;

describe('importBom', () => {
  it('部品を保存し、プロジェクト JSON の往復でも消えない', () => {
    const out = importBom(project(), bom([item('a'), item('b', 'crypto')]), { scope: 'app', node: 'C1', importedAt: AT });
    expect(out).toMatchObject({ stored: 2, truncated: 0, byKind: { software: 1, crypto: 1 }, linked: true });
    const parts = deserializeProject(roundTrip(out.project))?.bomComponents ?? [];
    expect(parts).toHaveLength(2);
    expect(parts[0].source).toMatchObject({ format: 'cyclonedx', product: 'example', scope: 'app' });
    expect(parts.every((p) => p.subject?.nodeId !== undefined)).toBe(true);
  });
  it('--node が無ければ未対応として保存し、推測で結びつけない', () => {
    const out = importBom(project(), bom([item('a')]), { scope: 'app', importedAt: AT });
    expect(out.linked).toBe(false);
    expect(out.project.bomComponents?.[0].subject).toBeUndefined();
  });
  it('図に無いノードの指定は報告し、未対応にする', () => {
    const out = importBom(project(), bom([item('a')]), { scope: 'app', node: 'C99', importedAt: AT });
    expect(out).toMatchObject({ badNodeRef: 'C99', linked: false });
  });
  it('同じ部品は 1 件にする', () => {
    expect(importBom(project(), bom([item('a'), item('a')]), { scope: 'app', importedAt: AT }).stored).toBe(1);
  });
  it('取り込み直しは同じ形式・同じ scope だけを置き換える', () => {
    const first = importBom(project(), bom([item('a')]), { scope: 'x', importedAt: AT });
    const other = importBom(roundTrip(first.project), bom([item('b')], 'spdx'), { scope: 'x', importedAt: AT });
    const third = importBom(roundTrip(other.project), bom([item('c')]), { scope: 'x', importedAt: AT });
    expect(third.project.bomComponents?.map((c) => c.externalId).sort()).toEqual(['b', 'c']);
  });
  it('上限を超えたら暗号と AI を優先して残し、切った件数を返す', () => {
    const many = Array.from({ length: MAX_BOM_COMPONENTS }, (_, i) => item(`lib-${i}`));
    const out = importBom(project(), bom([...many, item('alg', 'crypto'), item('model', 'ai-model')]), { scope: 'x', importedAt: AT });
    expect(out.stored).toBe(MAX_BOM_COMPONENTS);
    expect(out.truncated).toBe(2);
    const kinds = out.project.bomComponents?.map((c) => c.kind) ?? [];
    expect(kinds).toContain('crypto');
    expect(kinds).toContain('ai-model');
    expect(deserializeProject(roundTrip(out.project))).not.toBeNull();
  });
  it('読み込んだ SPDX をそのまま取り込める', () => {
    const parsed = parseBom({ spdxVersion: 'SPDX-2.3', packages: [{ SPDXID: 'SPDXRef-A', name: 'a' }] });
    if (!parsed.ok) throw new Error(parsed.error);
    expect(importBom(project(), parsed, { scope: 'x', importedAt: AT }).project.bomComponents?.[0].source.format).toBe('spdx');
  });
  it('報告に保存しなかった情報を明記する', () => {
    const out = importBom(project(), bom([item('a')]), { scope: 'x', importedAt: AT });
    expect(bomReportToMarkdown(out)).toContain('依存関係');
    expect(bomReportToJson(out)).toMatchObject({ kind: 'cyberriskscape-sbom-import-report', stored: 1 });
  });
});

describe('importBom（vulnerabilities・ライセンス）', () => {
  const fixture = (name: string) => {
    const parsed = parseBom(JSON.parse(readFileSync(new URL(`../features/bom-import/__fixtures__/${name}`, import.meta.url), 'utf-8')));
    if (!parsed.ok) throw new Error(parsed.error);
    return parsed;
  };
  it('CycloneDX の vulnerabilities を指摘として保存し、ライセンスは部品に残り、往復しても消えない', () => {
    const out = importBom(project(), fixture('sample-vex.cdx.json'), { scope: 'app', node: 'C1', importedAt: AT });
    expect(out.findings).toEqual({ stored: 3, excluded: 4, truncated: 0, withoutAffects: 2 });
    const back = deserializeProject(roundTrip(out.project));
    expect(back?.findings?.every((f) => f.source.product === 'CycloneDX' && f.source.scope === 'app' && f.subject !== undefined)).toBe(true);
    expect(back?.bomComponents?.find((c) => c.name === 'example-lib')?.licenses).toEqual(['MIT', '(Apache-2.0 OR GPL-2.0-only)']);
    expect(bomReportToMarkdown(out)).toContain('指摘 3 件（除外 4 件）');
    expect(bomReportToJson(out)).toMatchObject({ findings: { stored: 3, excluded: 4 } });
  });
  it('--node が無ければ指摘も未結合', () => {
    const out = importBom(project(), fixture('sample-vex.cdx.json'), { scope: 'app', importedAt: AT });
    expect(out.project.findings?.every((f) => f.subject === undefined)).toBe(true);
  });
  it('取り込み直しは CycloneDX × scope の指摘だけを置き換え、他の指摘は残す', () => {
    const first = importBom(project(), fixture('sample-vex.cdx.json'), { scope: 'app', importedAt: AT });
    const other = importBom(roundTrip(first.project), fixture('sample-vex.cdx.json'), { scope: 'other', importedAt: AT });
    expect(other.project.findings).toHaveLength(6);
    // vulnerabilities の無い BOM で app を取り込み直すと app の指摘は空になり、other は残る
    const empty = parseBom({ bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ type: 'library', name: 'a' }] });
    if (!empty.ok) throw new Error(empty.error);
    const again = importBom(roundTrip(other.project), empty, { scope: 'app', importedAt: AT });
    expect(again.project.findings).toHaveLength(3);
    expect(again.project.findings?.every((f) => f.source.scope === 'other')).toBe(true);
  });
  it('SPDX は指摘に触れない', () => {
    const first = importBom(project(), fixture('sample-vex.cdx.json'), { scope: 'app', importedAt: AT });
    const spdx = importBom(roundTrip(first.project), fixture('sample-licenses.spdx.json'), { scope: 'app', importedAt: AT });
    expect(spdx.project.findings).toHaveLength(3);
    expect(spdx.findings.stored).toBe(0);
    expect(spdx.project.bomComponents?.find((c) => c.name === 'declared-lib')?.licenses).toEqual(['BSD-3-Clause']);
  });
});
