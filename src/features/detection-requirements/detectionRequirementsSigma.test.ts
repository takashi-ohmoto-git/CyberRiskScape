import { parseAllDocuments } from 'yaml';
import { describe, expect, it } from 'vitest';
import type { DetectionRequirements, DetectionRequirementEntry } from './buildDetectionRequirements';
import { deterministicUuid, detectionRequirementsToSigma, SIGMA_DETECTION_PLACEHOLDER } from './detectionRequirementsSigma';
import { getDetectionRequirements } from './requirements';

const entry = (id: string, threat: string): DetectionRequirementEntry => {
  const r = getDetectionRequirements('ja').find((x) => x.id === id)!;
  return { id, title: r.title, watch: r.watch, logs: r.logs, attack: r.attack ?? [], threatNames: [threat] };
};

const d = (system = '架空のポータル'): DetectionRequirements => ({
  locale: 'ja',
  product: 'CyberRiskScape',
  system,
  layer: 'L1',
  generatedAt: '2026-11-15',
  pathBased: true,
  totalRoutes: 1,
  routes: [],
  nodes: [
    { id: 'C1', label: 'ポータル', type: 'FRONTEND_SERVER', routeHits: 1, log: null, requirements: [entry('web-exploit-and-shell', 'Web シェル'), entry('llm-abuse', 'LLM の悪用')] },
    { id: 'C2', label: '業務 API', type: 'BACKEND_API', routeHits: 1, log: null, requirements: [entry('web-exploit-and-shell', 'コード実行')] },
  ],
});

const rules = (text: string) => parseAllDocuments(text).map((doc) => doc.toJS() as Record<string, unknown>);

describe('deterministicUuid', () => {
  it('同じ文字列 → 同じ UUID（version 8）。違う文字列 → 違う UUID', () => {
    const a = deterministicUuid('x|y');
    expect(a).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(deterministicUuid('x|y')).toBe(a);
    expect(deterministicUuid('x|z')).not.toBe(a);
  });
});

describe('detectionRequirementsToSigma', () => {
  it('要件ごとに 1 本。当たるノード・脅威をまとめ、必須の項目（title・logsource・detection・condition）を持つ', () => {
    const out = rules(detectionRequirementsToSigma(d()));
    expect(out).toHaveLength(2);
    const web = out.find((r) => (r.threat_model as { requirement: string }).requirement === 'web-exploit-and-shell')!;
    expect(web.title).toBeTruthy();
    expect(web.status).toBe('unsupported');
    expect(web.logsource).toMatchObject({ category: 'webserver' });
    expect(web.detection).toEqual({ selection: { 'field_to_define|expand': SIGMA_DETECTION_PLACEHOLDER }, condition: 'selection' });
    expect(web.tags).toEqual(['attack.t1190', 'attack.t1505.003']);
    expect(web.threat_model).toMatchObject({ nodes: ['C1 ポータル', 'C2 業務 API'], threats: ['Web シェル', 'コード実行'] });
    expect(String(web.description)).toContain('そのままでは動かない');
  });

  it('対応表に Sigma のログの種類が無い要件は category: application にし、必要なログを definition に書く', () => {
    const llm = rules(detectionRequirementsToSigma(d())).find((r) => (r.threat_model as { requirement: string }).requirement === 'llm-abuse')!;
    expect((llm.logsource as Record<string, string>).category).toBe('application');
    expect((llm.logsource as Record<string, string>).definition).toContain('LLM');
  });

  it('id は書き出し直しても同じで、システム名が違えば変わる', () => {
    const id = (s?: string) => rules(detectionRequirementsToSigma(d(s)))[0].id;
    expect(id()).toBe(id());
    expect(id('別のシステム')).not.toBe(id());
  });

  it('要件が無ければ空', () => {
    expect(detectionRequirementsToSigma({ ...d(), nodes: [] })).toBe('');
  });
});
