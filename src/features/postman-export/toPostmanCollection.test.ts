import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { POSTMAN_SCHEMA_URL, toPostmanCollection } from './toPostmanCollection';
import { getTestTemplates } from './testTemplates';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';
import { kongToLayer } from '../kong-import/kongToLayer';
import { layerToProject } from '../kong-import/toProject';
import { analyzeProject } from '../../cli/analyze';

type Item = { name: string; request: { url: string; header: { key: string; value: string }[] }; event: unknown[] };
type Folder = { name: string; item: Item[] };

function sampleInput() {
  const r = kongToLayer(readFileSync('guide/templates/kong-ai-gateway.yaml', 'utf-8'));
  if (!r.ok) throw new Error(r.error);
  const [result] = analyzeProject(layerToProject(r.layer));
  return result.input;
}

describe('test templates', () => {
  it('対応表の canonicalId はすべて同梱の脅威ライブラリに実在する', () => {
    const known = new Set(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.canonicalId));
    for (const tpl of getTestTemplates('ja')) {
      for (const c of tpl.match.canonicalIds) expect(known.has(c), `${tpl.id}: ${c}`).toBe(true);
    }
  });

  it('英語オーバーレイはすべてのテンプレートの name / purpose を訳している', () => {
    const ja = getTestTemplates('ja');
    const en = getTestTemplates('en');
    expect(en.map((t) => t.id)).toEqual(ja.map((t) => t.id));
    en.forEach((t, i) => {
      expect(t.name).not.toBe(ja[i].name);
      expect(t.purpose).not.toBe(ja[i].purpose);
    });
  });
});

describe('toPostmanCollection', () => {
  it('v2.1 のスキーマを宣言し、ノードごとのフォルダにテスト付きのリクエストを置く', () => {
    const { collection, summary } = toPostmanCollection(sampleInput());
    expect((collection.info as { schema: string }).schema).toBe(POSTMAN_SCHEMA_URL);
    const folders = collection.item as Folder[];
    expect(folders.length).toBeGreaterThan(0);
    const items = folders.flatMap((f) => f.item);
    expect(items).toHaveLength(summary.requests);
    for (const item of items) expect(item.event).toHaveLength(1);
    expect(summary.coveredThreats).toBeGreaterThan(0);
    expect(summary.uncoveredThreats).toBeGreaterThan(0);
  });

  it('$NODE を ElementalID に置き換え、参照する変数をすべて宣言する', () => {
    const { collection } = toPostmanCollection(sampleInput());
    const dump = JSON.stringify(collection.item);
    expect(dump).not.toContain('$NODE');
    const declared = new Set((collection.variable as { key: string }[]).map((v) => v.key));
    const referenced = new Set([
      ...[...dump.matchAll(/\{\{([\w-]+)\}\}/g)].map((m) => m[1]),
      ...[...dump.matchAll(/pm\.variables\.get\(\\"([\w-]+)\\"\)/g)].map((m) => m[1]),
    ]);
    expect(referenced.has('system_prompt_marker')).toBe(true);
    for (const key of referenced) expect(declared.has(key), key).toBe(true);
  });

  it('サンプル構成で期待するテストが出る（未認証・平文・BOLA・カナリア・MCP）', () => {
    const { collection } = toPostmanCollection(sampleInput());
    const names = (collection.item as Folder[]).flatMap((f) => f.item.map((i) => i.name));
    expect(names).toEqual(
      expect.arrayContaining([
        '認証なしのリクエストが拒否されるか',
        'http（平文）で接続できないか',
        '他人のレコードを参照できないか（BOLA）',
        '指示の上書きに従わないか（カナリア文字列）',
        'MCP のツール記述子に隠し指示が無いか',
      ]),
    );
  });

  it('同じノード × 同じテンプレートは 1 件にまとめる', () => {
    const { collection } = toPostmanCollection(sampleInput());
    for (const folder of collection.item as Folder[]) {
      const names = folder.item.map((i) => i.name);
      expect(new Set(names).size).toBe(names.length);
    }
  });
});
