import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { NodeAssetModalBody, bomForTab, countAssetViews, countNodeAssetModes, type NodeAssetMode } from './NodeAssetModal';
import type { AssetViews } from '../../features/asset-view/buildAssetViews';
import type { Asset, AssetSubject, BomComponent, BomKind } from '../../core/model/types';
import type { ManualAssetError } from '../../features/asset-view/manualAsset';

const subject: AssetSubject = { layer: 'L1', nodeId: 'n1' };
const views: AssetViews = {
  hosts: [{ host: '203.0.113.10', domains: ['www.example.com'], ports: ['443/https'], technologies: [], subjects: [subject] }],
  sbom: [],
  requests: [],
  apis: [],
};
const empty: AssetViews = { hosts: [], sbom: [], requests: [], apis: [] };
const resolve = () => ({ label: 'C1 公開サイト', findings: 0 });
const render = (v: AssetViews) =>
  renderToStaticMarkup(
    <NodeAssetModalBody title="C1 公開サイト" views={v} mode="hosts" onModeChange={() => {}} resolve={resolve} />,
  );

describe('NodeAssetModalBody', () => {
  it('結びついた資産がある → タイトルとホストを表示する', () => {
    const html = render(views);
    expect(html).toContain('C1 公開サイト');
    expect(html).toContain('203.0.113.10');
  });

  it('資産が全て 0 件 → 空の案内を表示する', () => {
    const html = render(empty);
    expect(html).toContain('このノードに結びついた資産はありません');
    expect(html).not.toContain('<table');
  });
});

describe('countAssetViews', () => {
  it('API はグループ内のエンドポイント数を数える', () => {
    const c = countAssetViews({ ...empty, apis: [{ product: 'P', fromDefinition: false, endpoints: [{}, {}] as never }] });
    expect(c.apis).toBe(2);
  });
});

describe('部品表のタブ（SBOM・AI BOM・CBOM）', () => {
  const part = (name: string, kind: BomKind): BomComponent => ({
    id: name,
    source: { format: 'cyclonedx', product: 'x', importedAt: '2026-11-08T00:00:00Z' },
    externalId: name,
    identifiers: [],
    kind,
    name,
    subject,
  });
  const bomViews: AssetViews = {
    ...empty,
    sbom: [part('lib-a', 'software'), part('misc', 'other'), part('model-x', 'ai-model'), part('data-y', 'dataset'), part('rsa-2048', 'crypto')],
  };
  const renderTab = (mode: NodeAssetMode) =>
    renderToStaticMarkup(
      <NodeAssetModalBody title="C1" views={bomViews} mode={mode} onModeChange={() => {}} resolve={resolve} />,
    );

  it('種類で振り分ける → SBOM はソフトウェア・その他、AI BOM は AI モデル・データセット、CBOM は暗号', () => {
    expect(bomForTab(bomViews.sbom, 'sbom').map((c) => c.name)).toEqual(['lib-a', 'misc']);
    expect(bomForTab(bomViews.sbom, 'aibom').map((c) => c.name)).toEqual(['model-x', 'data-y']);
    expect(bomForTab(bomViews.sbom, 'cbom').map((c) => c.name)).toEqual(['rsa-2048']);
    expect(countNodeAssetModes(bomViews)).toMatchObject({ sbom: 2, aibom: 2, cbom: 1 });
  });

  it('CBOM タブ → 暗号の部品だけを表に出し、タブ見出しに AI BOM・CBOM がある', () => {
    const html = renderTab('cbom');
    expect(html).toContain('rsa-2048');
    expect(html).not.toContain('lib-a');
    expect(html).not.toContain('model-x');
    expect(html).toContain('AI BOM');
    expect(html).toContain('CBOM');
  });

  it('AI BOM タブ → AI モデル・データセットだけを出す', () => {
    const html = renderTab('aibom');
    expect(html).toContain('model-x');
    expect(html).toContain('data-y');
    expect(html).not.toContain('rsa-2048');
  });
});

describe('手入力の資産（ManualAssetEditor）', () => {
  const asset = (id: string, host: string): Asset => ({
    id,
    source: { format: 'manual', product: 'Manual', importedAt: '2026-11-08T00:00:00Z' },
    externalId: id,
    identifiers: [],
    kind: 'service',
    host,
    port: 8443,
    subject,
  });
  const renderManual = (assets: Asset[], v: AssetViews, error?: ManualAssetError, mode: NodeAssetMode = 'hosts') =>
    renderToStaticMarkup(
      <NodeAssetModalBody
        title="C1"
        views={v}
        mode={mode}
        onModeChange={() => {}}
        resolve={resolve}
        manual={{ manualAssets: assets, onAdd: () => true, onRemove: () => {}, error }}
      />,
    );

  it('手入力の資産がある → ホストと削除ボタンを一覧に出す', () => {
    const html = renderManual([asset('m1', 'app.example.com')], views);
    expect(html).toContain('app.example.com');
    expect(html).toContain('削除');
  });

  it('手入力の資産が無い（取り込み資産だけ） → 一覧は空で削除ボタンを出さない', () => {
    const html = renderManual([], views);
    expect(html).toContain('203.0.113.10');
    expect(html).toContain('手入力した資産はありません');
    expect(html).not.toContain('削除');
  });

  it('資産が 0 件 → 空の案内と追加フォームの両方を出す', () => {
    const html = renderManual([], empty);
    expect(html).toContain('このノードに結びついた資産はありません');
    expect(html).toContain('追加');
    expect(html).toContain('for="manual-asset-host"');
  });

  it('エラーコードを渡す → 翻訳したメッセージを出す', () => {
    expect(renderManual([], empty, 'portInvalid')).toContain('ポートは 1〜65535');
    expect(renderManual([], empty, 'duplicate')).toContain('同じ資産がすでにあります');
  });

  const endpoint: Asset = {
    ...asset('m2', 'api.example.com'),
    kind: 'endpoint',
    url: 'https://api.example.com/v1/runs',
    method: 'POST',
  };

  it('ホスト・ドメインのタブ → ホストの入力欄だけを出し、一覧にエンドポイントは載せない', () => {
    const html = renderManual([asset('m1', 'app.example.com'), endpoint], empty);
    expect(html).toContain('ホストを手入力で追加');
    expect(html).toContain('for="manual-asset-host"');
    expect(html).not.toContain('for="manual-asset-url"');
    expect(html).toContain('app.example.com');
    expect(html).not.toContain('/v1/runs');
  });

  it.each(['apis', 'requests'] as const)('%s のタブ → エンドポイントの入力欄とメソッドのプルダウンを出す', (mode) => {
    const html = renderManual([asset('m1', 'app.example.com'), endpoint], empty, undefined, mode);
    expect(html).toContain('エンドポイントを手入力で追加');
    expect(html).toContain('for="manual-asset-url"');
    expect(html).not.toContain('for="manual-asset-host"');
    expect(html).toContain('<select id="manual-asset-method"');
    for (const m of ['未指定', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']) expect(html).toContain(`>${m}</option>`);
    expect(html).toContain('/v1/runs');
    expect(html).not.toContain('app.example.com');
  });

  it.each(['sbom', 'aibom', 'cbom'] as const)('%s のタブ → 手入力のフォームを出さない', (mode) => {
    const html = renderManual([], empty, undefined, mode);
    expect(html).not.toContain('<form');
    expect(html).not.toContain('手入力で追加');
  });

  it('資産が 0 件でもタブを出す（入力先を選べる）', () => {
    expect(renderManual([], empty)).toContain('aria-pressed');
  });
});
