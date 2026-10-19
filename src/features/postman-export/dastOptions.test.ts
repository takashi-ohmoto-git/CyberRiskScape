import { describe, expect, it, vi } from 'vitest';
import { VarsFileSchema, applyVariableValues, filterByBaseUrl } from './dastOptions';

type Item = { name: string; request: { method: string; url: string }; event: { script: { exec: string[] } }[] };
type Folder = { name: string; item: Item[] };

const req = (name: string, url: string, exec: string[] = []): Item => ({
  name,
  request: { method: 'GET', url },
  event: [{ script: { exec } }],
});

function fixture() {
  return {
    info: { name: 'x' },
    variable: [
      { key: 'C3_admin_url', value: 'https://{{C3_host}}:8444' },
      { key: 'C3_host', value: '' },
      { key: 'C7_host', value: '' },
      { key: 'C7_path', value: '/' },
      { key: 'object_id_user_b', value: '' },
      { key: 'token_user_a', value: '' },
    ],
    item: [
      {
        name: 'C7 api',
        item: [
          req('https', 'https://{{C7_host}}{{C7_path}}'),
          req('plain', 'http://{{C7_host}}{{C7_path}}'),
          req('auth', 'https://{{C7_host}}/me', ['pm.variables.get("token_user_a")']),
        ],
      },
      { name: 'C3 admin', item: [req('admin', '{{C3_admin_url}}/status')] },
      { name: 'C9 other', item: [req('other', 'https://other.example.net/')] },
    ],
  };
}

const folders = (c: Record<string, unknown>) => c.item as Folder[];
const keys = (c: Record<string, unknown>) => (c.variable as { key: string }[]).map((v) => v.key);

describe('VarsFileSchema', () => {
  it('文字列だけの平らなオブジェクトを受け付け、それ以外は拒否する', () => {
    expect(VarsFileSchema.safeParse({ a: 'b' }).success).toBe(true);
    expect(VarsFileSchema.safeParse({ a: 1 }).success).toBe(false);
    expect(VarsFileSchema.safeParse(['a']).success).toBe(false);
  });
});

describe('applyVariableValues', () => {
  it('一致するキーの値を埋め、コレクションに無いキーと token_ を埋めたキーを返す', () => {
    const log = vi.spyOn(console, 'log');
    const out = applyVariableValues(fixture(), { C7_host: 'api.example.com', token_user_a: 'secret', nope: 'x' });
    const v = Object.fromEntries((out.collection.variable as { key: string; value: string }[]).map((x) => [x.key, x.value]));
    expect(v.C7_host).toBe('api.example.com');
    expect(v.token_user_a).toBe('secret');
    expect(v.C3_host).toBe('');
    expect(out.unknownKeys).toEqual(['nope']);
    expect(out.filledTokenKeys).toEqual(['token_user_a']);
    expect(log).not.toHaveBeenCalled();
    log.mockRestore();
  });

  it('入力を変更しない', () => {
    const input = fixture();
    const snapshot = JSON.stringify(input);
    applyVariableValues(input, { C7_host: 'h' });
    expect(JSON.stringify(input)).toBe(snapshot);
  });
});

describe('filterByBaseUrl', () => {
  const withHosts = () =>
    applyVariableValues(fixture(), { C7_host: 'api.example.com', C3_host: 'api.example.com' }).collection;

  it('base URL 配下だけ残し、http:// と :8444 の管理 URL を除く（末尾スラッシュは無視）', () => {
    const out = filterByBaseUrl(withHosts(), 'https://api.example.com/');
    const names = folders(out.collection).flatMap((f) => f.item.map((i) => i.name));
    expect(names).toEqual(['https', 'auth']);
    expect(out.kept).toBe(2);
    expect(out.total).toBe(5);
    // URL はテンプレートのまま
    expect(folders(out.collection)[0].item[0].request.url).toBe('https://{{C7_host}}{{C7_path}}');
  });

  it('似たホスト名（https://api.example.com.evil.net）には一致しない', () => {
    const c = applyVariableValues(fixture(), { C7_host: 'api.example.com.evil.net' }).collection;
    expect(filterByBaseUrl(c, 'https://api.example.com').kept).toBe(0);
  });

  it('空になったフォルダを除く', () => {
    const out = filterByBaseUrl(withHosts(), 'https://api.example.com');
    expect(folders(out.collection).map((f) => f.name)).toEqual(['C7 api']);
  });

  it('参照されなくなった変数を除き、他の変数経由・スクリプト経由の参照は残す', () => {
    const c = applyVariableValues(fixture(), { C7_host: 'a.example.com', C3_host: 'a.example.com' }).collection;
    // 管理 URL だけ残る base URL では、{{C3_admin_url}} 経由で C3_host も残る
    const admin = filterByBaseUrl(c, 'https://a.example.com:8444');
    expect(admin.kept).toBe(1);
    expect(keys(admin.collection)).toEqual(['C3_admin_url', 'C3_host']);
    const main = filterByBaseUrl(c, 'https://a.example.com');
    expect(keys(main.collection)).toEqual(['C7_host', 'C7_path', 'token_user_a']);
  });

  it('0 件でも空のコレクションを返し、入力を変更しない', () => {
    const input = fixture();
    const snapshot = JSON.stringify(input);
    const out = filterByBaseUrl(input, 'https://api.example.com');
    expect(out.kept).toBe(0);
    expect(out.collection.item).toEqual([]);
    expect(out.collection.variable).toEqual([]);
    expect(JSON.stringify(input)).toBe(snapshot);
  });
});
