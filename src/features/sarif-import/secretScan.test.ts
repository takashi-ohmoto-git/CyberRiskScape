import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseSarif } from './parseSarif';
import { sarifToFindings } from './sarifToFindings';
import { BUNDLED_SARIF_CATEGORIES, loadSarifCategories } from './sarifCategories';
import { extractSecretDetails } from './secretDetails';
import { BUNDLED_FINDING_MAP } from '../findings-report/findingMap';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';
import { importSarif, sarifReportToJson, sarifReportToMarkdown } from '../../cli/importSarif';

/** 秘密の走査の SARIF と同じ形の架空のデータ（秘密の値・作者・メールアドレスを含む）。 */
const raw = JSON.parse(readFileSync(new URL('./__fixtures__/secret-scan.sarif', import.meta.url), 'utf8')) as unknown;
const PROJECT = new URL('../../cli/__fixtures__/sample-project.json', import.meta.url);
const secrets = BUNDLED_SARIF_CATEGORIES.find((c) => c.id === 'secrets')!;

/** 保存してはいけない値（秘密の値・作者・メールアドレス・コミットメッセージ）。 */
const FORBIDDEN = /EXAMPLE-SECRET-VALUE|dev@example\.com|Example Developer|add config/;

function convert(withCategory = true) {
  const parsed = parseSarif(raw);
  if (!parsed.ok) throw new Error(parsed.error);
  return sarifToFindings({
    runs: parsed.runs,
    map: BUNDLED_FINDING_MAP,
    scope: 'repo',
    importedAt: '2026-11-15T00:00:00Z',
    ...(withCategory ? { category: secrets } : {}),
  });
}

describe('SARIF の分類（秘密の走査）', () => {
  it('同梱の分類を読め、canonicalId は脅威ライブラリに実在する', () => {
    const known = new Set(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.canonicalId));
    for (const c of BUNDLED_SARIF_CATEGORIES) for (const id of c.canonicalIds) expect(known.has(id), id).toBe(true);
    expect(secrets).toMatchObject({ canonicalIds: ['credential-sprawl'], defaultSeverity: 'High', allowRawReport: true });
    expect(() => loadSarifCategories('schemaVersion: 1\ncategories:\n  - id: a\n    title: a\n    canonicalIds: [x]\n    nodeTypes: [X]\n    defaultSeverity: High\n    useMessageAsTitle: false\n  - id: a\n    title: a\n    canonicalIds: [x]\n    nodeTypes: [X]\n    defaultSeverity: High\n    useMessageAsTitle: false\n')).toThrow();
  });

  it('分類を指定すると全結果を同じ脅威に結び、深刻度が無ければ既定（High）、題名に message を使わない', () => {
    const { findings } = convert();
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.canonicalIds.includes('credential-sprawl') && f.severity === 'High')).toBe(true);
    expect(findings.map((f) => f.title)).toEqual(['Cloud access key', 'Generic API key']);
  });

  it('同じコミットの複数の秘密を 1 件にまとめず、秘密の値・作者・メールアドレスを指摘に入れない', () => {
    const { findings } = convert(false);
    expect(findings).toHaveLength(2);
    expect(new Set(findings.map((f) => f.id)).size).toBe(2);
    expect(JSON.stringify(findings)).not.toMatch(FORBIDDEN);
  });

  it('partialFingerprints のハッシュの項目は従来どおり指摘の ID に使う', () => {
    const sarif = {
      version: '2.1.0',
      runs: [{ tool: { driver: { name: 'x' } }, results: [{ ruleId: 'r', partialFingerprints: { author: 'someone', primaryLocationLineHash: 'abc123' } }] }],
    };
    const parsed = parseSarif(sarif);
    if (!parsed.ok) throw new Error(parsed.error);
    const { findings } = sarifToFindings({ runs: parsed.runs, map: BUNDLED_FINDING_MAP, scope: 's', importedAt: 't' });
    expect(findings[0].externalId).toBe('abc123');
  });

  it('生の情報は extractSecretDetails でだけ取り出せる（場所・付随情報・秘密の値）', () => {
    const d = extractSecretDetails(raw);
    expect(d[0]).toMatchObject({ rule: 'cloud-access-key', location: 'config/app.env:3', secret: 'EXAMPLE-SECRET-VALUE-0001' });
    expect(d[0].context.email).toBe('dev@example.com');
  });
});

describe('importSarif（秘密の走査）', () => {
  const project = () => JSON.parse(readFileSync(PROJECT, 'utf8')) as unknown;
  const parsed = () => {
    const p = parseSarif(raw);
    if (!p.ok) throw new Error(p.error);
    return p;
  };

  it('既定は件数の内訳だけで、報告にもプロジェクトにも秘密の値を出さない', () => {
    const out = importSarif(project(), parsed(), { scope: 'repo', category: secrets });
    expect(out.breakdown).toEqual({ byRule: [{ rule: 'Cloud access key', count: 1 }, { rule: 'Generic API key', count: 1 }], files: 2 });
    const md = sarifReportToMarkdown(out);
    expect(md).toContain('--show-secrets');
    expect(md).not.toMatch(FORBIDDEN);
    expect(JSON.stringify(sarifReportToJson(out))).not.toMatch(FORBIDDEN);
    expect(JSON.stringify(out.project)).not.toMatch(FORBIDDEN);
    expect(md).toContain('CREDENTIAL');
  });

  it('--show-secrets では報告にだけ生の情報を出し、プロジェクト JSON には入れない', () => {
    const out = importSarif(project(), parsed(), { scope: 'repo', category: secrets, rawDetails: extractSecretDetails(raw) });
    const md = sarifReportToMarkdown(out);
    expect(md).toContain('EXAMPLE-SECRET-VALUE-0001');
    expect(md).toContain('秘密の値を含む');
    expect(JSON.stringify(sarifReportToJson(out))).toContain('dev@example.com');
    expect(JSON.stringify(out.project)).not.toMatch(FORBIDDEN);
  });
});
