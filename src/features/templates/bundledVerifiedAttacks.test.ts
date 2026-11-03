import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { analyzeResolvedProject, resolveProject } from '../../cli/analyze';
import { findingsForThreat } from '../pentest-import/matchFindings';
import { parseTemplateFromJson } from './io';

const read = (lng: string) =>
  readFileSync(new URL(`../../../guide/templates/artex-verified-attacks.${lng}.json`, import.meta.url), 'utf-8');

describe.each(['ja', 'en'])('同梱サンプル（%s）', (lng) => {
  it('プロジェクト全体として開け、指摘を保持する', () => {
    const r = parseTemplateFromJson(read(lng));
    expect(r.ok && r.project?.findings).toHaveLength(8);
  });

  it('全ての指摘が脅威カードに載る', () => {
    const resolved = resolveProject(JSON.parse(read(lng)));
    const threats = analyzeResolvedProject(resolved, { framework: 'ALL' }).flatMap((l) => l.threats);
    const shown = new Set(threats.flatMap((t) => findingsForThreat(resolved.findings ?? [], t).map((f) => f.id)));
    expect(shown.size).toBe(8);
  });

  it('架空の構成である（IP アドレス・URL・ドメインを含まない）', () => {
    const text = read(lng);
    expect(text).not.toMatch(/\b\d{1,3}(\.\d{1,3}){3}\b/);
    expect(text).not.toMatch(/https?:\/\//);
    expect(text).not.toMatch(/\b[a-z0-9-]+\.(com|net|org|jp|io|local)\b/i);
  });
});

describe('parseTemplateFromJson', () => {
  it('指摘の無いプロジェクト → 図だけとして扱う', () => {
    const p = JSON.parse(read('ja'));
    delete p.findings;
    const r = parseTemplateFromJson(JSON.stringify(p));
    expect(r.ok && r.project).toBeUndefined();
  });
});
