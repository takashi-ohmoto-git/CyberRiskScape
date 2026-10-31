import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseMcpScannerFindings } from './parseMcpScanner';
import { ciscoSeverityLabel, ciscoSeverityScore, parseSkillScannerFindings } from './parseSkillScanner';

const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(new URL(`./__fixtures__/${name}`, import.meta.url), 'utf-8'));

function must<T extends { ok: boolean }>(r: T): Extract<T, { ok: true }> {
  if (!r.ok) throw new Error('parse failed');
  return r as Extract<T, { ok: true }>;
}

describe('重大度の写し', () => {
  it('CRITICAL=5 HIGH=4 MEDIUM=3 LOW=2 INFO=0、ラベルへ戻せる', () => {
    expect(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'SAFE'].map(ciscoSeverityScore)).toEqual([5, 4, 3, 2, 0, 0]);
    expect([5, 4, 3, 2, 0].map(ciscoSeverityLabel)).toEqual(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
  });
});

describe('parseSkillScannerFindings', () => {
  it('単体: id・重大度・場所（skill_name/file:line）・分類を取り込む', () => {
    const p = must(parseSkillScannerFindings(fixture('skill-scanner-single.json')));
    expect(p.findings).toHaveLength(4);
    expect(p.findings[0]).toMatchObject({
      id: 'sk-001',
      severity: 4,
      location: 'invoice-helper/SKILL.md:12',
      origin: 'skill-scanner',
      aitech: 'AITech-1.1',
      aisubtech: 'AISubtech-1.1.1',
      aisubtechName: 'Instruction Manipulation',
    });
    expect(p.findings[1]).toMatchObject({ aitech: 'AITech-2.1', aisubtech: undefined });
    expect(p.findings[3]).toMatchObject({ severity: 0, aitech: undefined, location: 'invoice-helper/SKILL.md' });
  });

  it('複数スキル（results）を 1 つにまとめる', () => {
    const p = must(parseSkillScannerFindings(fixture('skill-scanner-multi.json')));
    expect(p.findings.map((f) => [f.id, f.severity, f.location])).toEqual([
      ['sk-101', 5, 'calendar-sync/scripts/sync.py:7'],
    ]);
  });

  it('秘密・自由記述・絶対パスを取り込まない', () => {
    const p = must(parseSkillScannerFindings(fixture('skill-scanner-single.json')));
    const text = JSON.stringify(p);
    for (const s of ['sk-live-XXXX', 'SECRET123', 'secret-dir', 'subprocess', 'secret-framework-mapping']) {
      expect(text).not.toContain(s);
    }
  });

  it('形式が違えばエラー', () => {
    expect(parseSkillScannerFindings({ foo: 1 }).ok).toBe(false);
    expect(parseSkillScannerFindings([]).ok).toBe(false);
  });
});

describe('parseMcpScannerFindings', () => {
  it('envelope: 1 指摘 = 項目×解析器×分類。SAFE で 0 件の解析器は出さない', () => {
    const p = must(parseMcpScannerFindings(fixture('mcp-scanner-envelope.json')));
    expect(p.findings.map((f) => f.id)).toEqual([
      'docs-server/search_docs/yara_analyzer/AISubtech-1.1.1',
      'docs-server/search_docs/yara_analyzer/AISubtech-12.1.5',
      'docs-server/readme/llm_analyzer/AISubtech-15.1.9',
    ]);
    expect(p.findings[0]).toMatchObject({
      severity: 4,
      location: 'docs-server/tool:search_docs',
      origin: 'mcp-scanner',
      aitech: 'AITech-1.1',
    });
    expect(p.findings[2]).toMatchObject({ severity: 2, location: 'docs-server/resource:readme' });
  });

  it('status が completed 以外の項目数を数える', () => {
    expect(must(parseMcpScannerFindings(fixture('mcp-scanner-envelope.json'))).incompleteItems).toBe(1);
  });

  it('配列・known-configs の 3 形式とも同じ指摘になる（設定ファイルのパスは使わない）', () => {
    const env = must(parseMcpScannerFindings(fixture('mcp-scanner-envelope.json')));
    const known = must(parseMcpScannerFindings(fixture('mcp-scanner-known-configs.json')));
    expect(known.findings.map((f) => f.id)).toEqual(env.findings.map((f) => f.id));
    expect(known.incompleteItems).toBe(1);
    const arr = must(parseMcpScannerFindings(fixture('mcp-scanner-array.json')));
    expect(arr.findings.map((f) => f.id)).toEqual(env.findings.slice(0, 2).map((f) => f.id));
    expect(JSON.stringify(known)).not.toContain('.cursor');
  });

  it('server_url・説明文・server_source・URL のクエリを取り込まない', () => {
    const text = JSON.stringify(must(parseMcpScannerFindings(fixture('mcp-scanner-envelope.json'))));
    for (const s of ['sk-live-XXXX', 'SECRET123', 'some-mcp-server', 'secret-dir', 'Hidden instruction']) {
      expect(text).not.toContain(s);
    }
  });

  it('分類が無いが指摘がある解析器は「分類なし」の指摘として残す', () => {
    const p = must(
      parseMcpScannerFindings([
        { status: 'completed', item_type: 'tool', tool_name: 't', findings: { yara_analyzer: { severity: 'MEDIUM', total_findings: 1 } } },
      ]),
    );
    expect(p.findings).toHaveLength(1);
    expect(p.findings[0]).toMatchObject({ severity: 3, aitech: undefined, aisubtech: undefined });
  });

  it('形式が違えばエラー', () => {
    expect(parseMcpScannerFindings('x').ok).toBe(false);
    expect(parseMcpScannerFindings({ a: 1 }).ok).toBe(false);
  });
});
