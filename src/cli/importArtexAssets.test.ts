import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { artexAssetsReportToJson, artexAssetsReportToMarkdown, importArtexAssets } from './importArtexAssets';
import { deserializeProject } from '../features/persistence/serialize';

const AT = '2026-11-04T00:00:00.000Z';
const project = () =>
  JSON.parse(readFileSync(new URL('../features/pentest-import/__fixtures__/sample-project.json', import.meta.url), 'utf-8'));
const roundTrip = (p: unknown) => JSON.parse(JSON.stringify(p));

const https = { host: '203.0.113.10', ip: '203.0.113.10', port: 443, serviceName: 'https', technologies: ['nginx'] };
const login = { host: '203.0.113.10', method: 'POST', url: 'https://203.0.113.10/login', params: [{ name: 'user', location: 'body' }] };

describe('importArtexAssets', () => {
  it('同じサービスの複数の行を 1 件にまとめ、技術を合わせる', () => {
    const out = importArtexAssets(
      project(),
      { services: [https, { ...https, technologies: ['php'], observedAt: '2026-11-04' }], endpoints: [], skippedBySource: 0 },
      { scope: 'task-a', importedAt: AT },
    );
    expect(out.services).toBe(1);
    expect(out.project.assets?.[0]).toMatchObject({ technologies: ['nginx', 'php'], observedAt: '2026-11-04' });
  });
  it('対応表のホストはノードに結びつき、プロジェクト JSON の往復でも消えない', () => {
    const out = importArtexAssets(
      project(),
      { services: [https], endpoints: [login], skippedBySource: 2 },
      { scope: 'task-a', nodeMap: { '203.0.113.10': 'C1' }, importedAt: AT },
    );
    expect(out.unlinkedHosts).toEqual([]);
    expect(out.skippedBySource).toBe(2);
    const assets = deserializeProject(roundTrip(out.project))?.assets ?? [];
    expect(assets).toHaveLength(2);
    expect(assets.every((a) => a.subject?.nodeId !== undefined)).toBe(true);
  });
  it('対応が無ければ未対応として保存し、推測で結びつけない', () => {
    const out = importArtexAssets(project(), { services: [https], endpoints: [], skippedBySource: 0 }, { scope: 'task-a', importedAt: AT });
    expect(out.unlinkedHosts).toEqual(['203.0.113.10']);
    expect(out.project.assets?.[0].subject).toBeUndefined();
  });
  it('図に無いノードの指定は報告し、未対応にする', () => {
    const out = importArtexAssets(
      project(),
      { services: [https], endpoints: [], skippedBySource: 0 },
      { scope: 'task-a', node: 'C99', importedAt: AT },
    );
    expect(out.badNodeRefs).toEqual(['C99']);
    expect(out.unlinkedHosts).toEqual(['203.0.113.10']);
  });
  it('取り込み直しは同じ scope だけを置き換える', () => {
    const input = { services: [https], endpoints: [], skippedBySource: 0 };
    const first = importArtexAssets(project(), input, { scope: 'task-a', importedAt: AT });
    const second = importArtexAssets(roundTrip(first.project), input, { scope: 'task-b', importedAt: AT });
    const third = importArtexAssets(roundTrip(second.project), { ...input, services: [] }, { scope: 'task-a', importedAt: AT });
    expect(third.project.assets?.map((a) => a.source.scope)).toEqual(['task-b']);
  });
  it('報告に件数と注意を載せる', () => {
    const out = importArtexAssets(project(), { services: [https], endpoints: [login], skippedBySource: 3 }, { scope: 'task-a', importedAt: AT });
    expect(artexAssetsReportToMarkdown(out)).toContain('サービス 1 件 / エンドポイント 1 件');
    expect(artexAssetsReportToJson(out)).toMatchObject({ kind: 'cyberriskscape-artex-assets-import-report', skippedBySource: 3 });
  });
});
