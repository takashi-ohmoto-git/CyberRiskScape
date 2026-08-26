import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ComplianceMapLoadError,
  findUnresolvedComplianceRefs,
  loadComplianceMap,
  makeComplianceKey,
  parseComplianceMapFile,
  type RawYamlFile,
} from './loadComplianceMap';
import {
  loadThreatLibrary,
  type RawYamlFile as ThreatRawYamlFile,
} from '../../threat-library/loader/loadThreatLibrary';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const COMPLIANCE_DIR = resolve(__dirname, '../../../data/compliance');
const THREAT_DIR = resolve(__dirname, '../../../data/threat-library');

function loadAllComplianceFiles(): RawYamlFile[] {
  const files = readdirSync(COMPLIANCE_DIR).filter(
    (f) => f.endsWith('.yaml') || f.endsWith('.yml'),
  );
  return files.map((name) => ({
    source: name,
    text: readFileSync(join(COMPLIANCE_DIR, name), 'utf-8'),
  }));
}

function loadAllThreatFiles(): ThreatRawYamlFile[] {
  const files = readdirSync(THREAT_DIR).filter(
    (f) => f.endsWith('.yaml') || f.endsWith('.yml'),
  );
  return files.map((name) => ({
    source: name,
    text: readFileSync(join(THREAT_DIR, name), 'utf-8'),
  }));
}

describe('loadComplianceMap - 同梱データ', () => {
  it('data/compliance 配下の YAML をすべてロードできる', () => {
    const result = loadComplianceMap(loadAllComplianceFiles());
    expect(result.index.size).toBeGreaterThan(0);
    expect(result.sources).toContain('nist-ai-rmf.yaml');
    expect(result.sources).toContain('jp-ai-business-guideline.yaml');
  });

  it('規格 ID は重複なく登録される', () => {
    const result = loadComplianceMap(loadAllComplianceFiles());
    expect(result.standards.has('nist-ai-rmf')).toBe(true);
    expect(result.standards.has('jp-ai-business-guideline')).toBe(true);
  });

  it('NIST AI RMF が GOVERN/MAP/MEASURE/MANAGE 全機能を含む', () => {
    const result = loadComplianceMap(loadAllComplianceFiles());
    const refs = (result.itemsByStandard.get('nist-ai-rmf') ?? []).map((i) => i.ref);
    expect(refs.some((r) => r.startsWith('GOVERN'))).toBe(true);
    expect(refs.some((r) => r.startsWith('MAP'))).toBe(true);
    expect(refs.some((r) => r.startsWith('MEASURE'))).toBe(true);
    expect(refs.some((r) => r.startsWith('MANAGE'))).toBe(true);
  });

  it('AI 事業者ガイドラインが共通の指針10項目と主体別指針を含む', () => {
    const result = loadComplianceMap(loadAllComplianceFiles());
    const refs = (result.itemsByStandard.get('jp-ai-business-guideline') ?? []).map(
      (i) => i.ref,
    );
    for (let i = 1; i <= 10; i++) {
      expect(refs).toContain(`共通の指針-${i}`);
    }
    expect(refs.some((r) => r.startsWith('開発者-'))).toBe(true);
    expect(refs.some((r) => r.startsWith('提供者-'))).toBe(true);
    expect(refs.some((r) => r.startsWith('利用者-'))).toBe(true);
  });

  it('(standard, ref) で逆引きできる', () => {
    const result = loadComplianceMap(loadAllComplianceFiles());
    const item = result.index.get(makeComplianceKey('nist-ai-rmf', 'MAP 4.1'));
    expect(item).toBeDefined();
    expect(item?.title).toContain('リスク');
  });
});

describe('loadComplianceMap - スキーマ検証', () => {
  it('未知の standard.id は拒否する', () => {
    const yaml = `
schemaVersion: 1
standard:
  id: unknown-standard
  title: "Unknown"
  url: "https://example.com"
items:
  - ref: "X 1.1"
    title: "X"
    summary: "test"
`;
    expect(() => parseComplianceMapFile(yaml, 'bad.yaml')).toThrow(ComplianceMapLoadError);
  });

  it('items が空の場合は拒否する', () => {
    const yaml = `
schemaVersion: 1
standard:
  id: nist-ai-rmf
  title: "NIST"
  url: "https://nist.gov"
items: []
`;
    expect(() => parseComplianceMapFile(yaml, 'empty.yaml')).toThrow(ComplianceMapLoadError);
  });

  it('schemaVersion が不一致だと拒否する', () => {
    const yaml = `
schemaVersion: 2
standard:
  id: nist-ai-rmf
  title: "NIST"
  url: "https://nist.gov"
items:
  - ref: "X 1.1"
    title: "X"
    summary: "test"
`;
    expect(() => parseComplianceMapFile(yaml, 'v2.yaml')).toThrow(ComplianceMapLoadError);
  });
});

describe('loadComplianceMap - 重複検知', () => {
  it('同一規格を 2 ファイルで定義すると throw', () => {
    const yaml = (label: string) => `
schemaVersion: 1
standard:
  id: nist-ai-rmf
  title: "NIST ${label}"
  url: "https://nist.gov"
items:
  - ref: "X 1.1"
    title: "X"
    summary: "test"
`;
    expect(() =>
      loadComplianceMap([
        { source: 'a.yaml', text: yaml('A') },
        { source: 'b.yaml', text: yaml('B') },
      ]),
    ).toThrow(/Duplicate standard/);
  });

  it('同一規格内で ref を重複させると throw', () => {
    const yaml = `
schemaVersion: 1
standard:
  id: nist-ai-rmf
  title: "NIST"
  url: "https://nist.gov"
items:
  - ref: "X 1.1"
    title: "X"
    summary: "first"
  - ref: "X 1.1"
    title: "X dup"
    summary: "second"
`;
    expect(() => loadComplianceMap([{ source: 'dup.yaml', text: yaml }])).toThrow(
      /Duplicate item/,
    );
  });
});

describe('loadComplianceMap - relatedTo リンク切れ', () => {
  it('存在しない (standard, ref) を relatedTo に書くと throw', () => {
    const yaml = `
schemaVersion: 1
standard:
  id: nist-ai-rmf
  title: "NIST"
  url: "https://nist.gov"
items:
  - ref: "X 1.1"
    title: "X"
    summary: "test"
    relatedTo:
      - { standard: jp-ai-business-guideline, ref: "missing-ref" }
`;
    expect(() => loadComplianceMap([{ source: 'dangling.yaml', text: yaml }])).toThrow(
      /Dangling relatedTo/,
    );
  });

  it('同梱データの relatedTo はすべて解決できる', () => {
    // loadComplianceMap が throw しないことが担保すれば十分。
    expect(() => loadComplianceMap(loadAllComplianceFiles())).not.toThrow();
  });
});

describe('findUnresolvedComplianceRefs', () => {
  it('マップに存在しない ref を持つ脅威ルールを検出する', () => {
    const map = loadComplianceMap(loadAllComplianceFiles());
    const unresolved = findUnresolvedComplianceRefs(map, [
      { id: 'test-rule-1', complianceRefs: [{ standard: 'nist-ai-rmf', ref: 'MAP 4.1' }] },
      {
        id: 'test-rule-2',
        complianceRefs: [{ standard: 'nist-ai-rmf', ref: 'NONEXISTENT 99.9' }],
      },
      { id: 'test-rule-3', complianceRefs: [{ standard: 'unknown-std', ref: 'X' }] },
    ]);
    expect(unresolved).toHaveLength(2);
    expect(unresolved.map((u) => u.ruleId)).toEqual(['test-rule-2', 'test-rule-3']);
  });

  it('同梱脅威ルール側 complianceRefs はすべてマップ内で解決できる', () => {
    const map = loadComplianceMap(loadAllComplianceFiles());
    const threats = loadThreatLibrary(loadAllThreatFiles());
    const unresolved = findUnresolvedComplianceRefs(map, threats.rules);
    expect(unresolved).toEqual([]);
  });
});
