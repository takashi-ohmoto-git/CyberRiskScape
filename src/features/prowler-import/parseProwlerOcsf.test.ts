import { describe, expect, it } from 'vitest';
import { parseProwlerOcsf, resourceLabel, stripUrlSecrets } from './parseProwlerOcsf';
import sample from './__fixtures__/sample.ocsf.json';

describe('parseProwlerOcsf', () => {
  it('配列を正規化し、crs-node タグの値だけ取り出す', () => {
    const r = parseProwlerOcsf(sample);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const first = r.findings[0];
    expect(first.checkId).toBe('s3_bucket_default_encryption');
    expect(first.status).toBe('PASS');
    expect(first.title).toBe('title of s3_bucket_default_encryption');
    expect(first.categories).toEqual(['encryption']);
    expect(first.resources[0]).toMatchObject({
      name: 'docs-bucket',
      type: 'AwsS3Bucket',
      service: 's3',
      region: 'ap-northeast-1',
      nodeTag: 'n-bucket',
    });
  });

  it('ミュート済みは除外し、MANUAL は残す', () => {
    const r = parseProwlerOcsf(sample);
    if (!r.ok) throw new Error('parse');
    expect(r.skipped).toEqual({ invalid: 0, muted: 1 });
    expect(r.findings.some((f) => f.status === 'MANUAL')).toBe(true);
    expect(r.findings).toHaveLength(16);
  });

  it('捨てる値（アカウント ID・資源の data・長文）が正規化結果に含まれない', () => {
    const r = parseProwlerOcsf(sample);
    if (!r.ok) throw new Error('parse');
    const text = JSON.stringify(r);
    expect(text).not.toContain('SECRET_RESOURCE_DATA_PAYLOAD');
    expect(text).not.toContain('RISKDETAILS_LONG_TEXT');
    expect(text).not.toContain('DESCRIPTION_TEXT_NOT_NEEDED');
    expect(text).not.toContain('o-sample');
    expect(text).not.toContain('sample-account');
  });

  it('形が違う入力はエラー、読めない項目は数える', () => {
    expect(parseProwlerOcsf('x').ok).toBe(false);
    expect(parseProwlerOcsf([{ foo: 1 }]).ok).toBe(false);
    const r = parseProwlerOcsf([{ foo: 1 }, { metadata: { event_code: 'a' }, status_code: 'PASS' }]);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.findings).toHaveLength(1);
      expect(r.skipped.invalid).toBe(1);
    }
  });

  it('URL の userinfo とクエリを捨てる', () => {
    expect(stripUrlSecrets('https://user:pass@example.com/a?token=XYZ#f')).toBe('https://example.com/a');
    expect(stripUrlSecrets('arn:aws:s3:::bucket')).toBe('arn:aws:s3:::bucket');
    const r = parseProwlerOcsf([
      {
        metadata: { event_code: 'a' },
        status_code: 'FAIL',
        resources: [{ uid: 'https://u:SECRETPW@h.example.com/x?k=SECRETQ', name: 'n' }],
      },
    ]);
    expect(JSON.stringify(r)).not.toMatch(/SECRETPW|SECRETQ/);
  });

  it('表示名は名前を優先し、アカウント ID を伏せる', () => {
    expect(resourceLabel({ name: 'b', uid: 'arn:aws:s3:::b' })).toBe('b');
    expect(resourceLabel({ uid: 'arn:aws:iam::123456789012:user/x' })).toBe('arn:aws:iam::*:user/x');
  });
});
