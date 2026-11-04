import { readFileSync } from 'node:fs';
import Ajv2019 from 'ajv/dist/2019';
import addFormats from 'ajv-formats';
import { describe, expect, it } from 'vitest';
import type { BomComponent } from '../../core/model/types';
import { buildSpdx } from './buildSpdx';
import { parseBom } from './parseBom';

const schema = JSON.parse(readFileSync(new URL('./__fixtures__/spdx-2.3.schema.json', import.meta.url), 'utf-8'));
const validate = (doc: unknown) => {
  const ajv = new Ajv2019({ strict: false, allErrors: true });
  addFormats(ajv);
  const check = ajv.compile(schema);
  return { ok: check(doc), errors: check.errors };
};

const SHA = 'b'.repeat(64);
const part = (id: string, over: Partial<BomComponent> = {}): BomComponent => ({
  id,
  source: { format: 'cyclonedx', product: 'x', scope: 's', importedAt: '2026-11-01T00:00:00.000Z' },
  externalId: id,
  identifiers: [],
  kind: 'software',
  name: id,
  ...over,
});
const OPTS = {
  name: 'example',
  created: '2026-11-05T01:02:03.456Z',
  documentNamespace: 'urn:uuid:00000000-0000-4000-8000-000000000000',
  toolVersion: '0.7.0',
};

describe('buildSpdx', () => {
  it('出力が SPDX 2.3 の公式スキーマに適合する', () => {
    const { document } = buildSpdx(
      [
        part('@scope/lib a', {
          version: '1.0.0',
          sourceType: 'library',
          identifiers: [
            { scheme: 'purl', value: 'pkg:npm/%40scope/lib@1.0.0' },
            { scheme: 'cpe', value: 'cpe:2.3:a:example:lib:1.0.0:*:*:*:*:*:*:*' },
            { scheme: 'sha-256', value: SHA },
          ],
        }),
        part('model', { kind: 'ai-model', sourceType: 'machine-learning-model' }),
      ],
      OPTS,
    );
    const r = validate(document);
    expect(r.errors).toBeNull();
    expect(r.ok).toBe(true);
  });
  it('部品が 0 件でもスキーマに適合する', () => {
    expect(validate(buildSpdx([], OPTS).document).ok).toBe(true);
  });
  it('暗号資産は出さず、件数を返して文書のコメントに書く', () => {
    const out = buildSpdx([part('lib'), part('ML-KEM', { kind: 'crypto', crypto: { assetType: 'algorithm' } })], OPTS);
    expect(out).toMatchObject({ packages: 1, omittedCrypto: 1 });
    expect(JSON.stringify(out.document)).not.toContain('ML-KEM"');
    expect((out.document.creationInfo as { comment: string }).comment).toContain('1 cryptographic asset(s) omitted');
  });
  it('AI モデルは用途 OTHER とコメントで示す', () => {
    const { document } = buildSpdx([part('model', { kind: 'ai-model' })], OPTS);
    expect((document.packages as object[])[0]).toMatchObject({ primaryPackagePurpose: 'OTHER', comment: 'AI model' });
  });
  it('SPDX → 共通モデル → SPDX で鍵が保たれる', () => {
    const { document } = buildSpdx(
      [
        part('left-pad', {
          version: '1.3.0',
          sourceType: 'library',
          identifiers: [
            { scheme: 'purl', value: 'pkg:npm/left-pad@1.3.0' },
            { scheme: 'sha-256', value: SHA },
          ],
        }),
      ],
      OPTS,
    );
    const parsed = parseBom(document);
    expect(parsed).toMatchObject({ ok: true, format: 'spdx', specVersion: 'SPDX-2.3' });
    expect(parsed.ok && parsed.items[0]).toMatchObject({
      name: 'left-pad',
      version: '1.3.0',
      identifiers: [
        { scheme: 'purl', value: 'pkg:npm/left-pad@1.3.0' },
        { scheme: 'sha-256', value: SHA },
      ],
    });
  });
});
