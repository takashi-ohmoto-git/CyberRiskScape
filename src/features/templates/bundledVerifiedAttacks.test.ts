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

  it('資産は文書用の IP と example.com だけを使う', () => {
    const { assets } = JSON.parse(read(lng)) as { assets: { host: string; ip?: string; domain?: string; url?: string }[] };
    expect(assets.length).toBeGreaterThan(0);
    for (const a of assets) {
      if (a.ip) expect(a.ip).toMatch(/^203\.0\.113\.\d{1,3}$/);
      if (a.domain) expect(a.domain).toMatch(/(^|\.)example\.com$/);
      if (a.url) expect(new URL(a.url).hostname).toMatch(/(^|\.)example\.com$/);
      expect(a.host).toMatch(/^203\.0\.113\.\d{1,3}$|(^|\.)example\.com$/);
    }
  });

  it('資産以外は架空の構成である（IP アドレス・URL・ドメインを含まない）', () => {
    const { assets: _assets, ...rest } = JSON.parse(read(lng)) as Record<string, unknown>;
    const text = JSON.stringify(rest);
    expect(text).not.toMatch(/\b\d{1,3}(\.\d{1,3}){3}\b/);
    expect(text).not.toMatch(/https?:\/\//);
    expect(text).not.toMatch(/\b[a-z0-9-]+\.(com|net|org|jp|io|local)\b/i);
  });
});

describe('parseTemplateFromJson', () => {
  it('指摘の無いプロジェクト → 図だけとして扱う', () => {
    const p = JSON.parse(read('ja'));
    delete p.findings;
    delete p.assets;
    const r = parseTemplateFromJson(JSON.stringify(p));
    expect(r.ok && r.project).toBeUndefined();
  });
  it('資産だけを持つプロジェクト → プロジェクト全体として扱う', () => {
    const p = JSON.parse(read('ja'));
    delete p.findings;
    const r = parseTemplateFromJson(JSON.stringify(p));
    expect(r.ok && r.project?.assets?.length).toBeGreaterThan(0);
  });
});
