import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse as parseYaml } from 'yaml';
import { buildRequirements, type RequirementsInput } from './buildRequirements';
import { requirementsToCsv, requirementsToJson, requirementsToMarkdown } from './requirementsOutput';
import { BUNDLED_STAGE_OVERLAY_EN, getStageMap, loadStageMap } from './stageMap';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';
import { EMPTY_PROJECT_META, type DiagramNode, type ThreatView } from '../../core/model/types';

const NOW = new Date('2026-11-07T12:00:00Z');

describe('requirement-maps（同梱データ）', () => {
  const text = readFileSync('data/requirement-maps/process-stages.yaml', 'utf-8');

  it('YAML がスキーマを通り、canonicalId はすべて同梱の脅威ライブラリに実在する', () => {
    const map = loadStageMap(text);
    const known = new Set(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.canonicalId));
    for (const c of Object.keys(map.stages)) expect(known.has(c), `stages: ${c}`).toBe(true);
    for (const def of map.contractorRequirements) {
      for (const c of def.triggers) expect(known.has(c), `${def.id}: ${c}`).toBe(true);
    }
    expect(Object.keys(map.stages).length).toBeGreaterThanOrEqual(30);
  });

  it('委託先の要件 id が重複していると読み込みに失敗する', () => {
    const one = `  - id: a\n    triggers: [x]\n    text: t\n`;
    const head = `schemaVersion: 1\nstageLabels: {design: a, implementation: b, verification: c, operation: d}\ndefault: [design]\nstages: {}\ncontractorRequirements:\n`;
    expect(() => loadStageMap(head + one + one)).toThrow(/duplicate/);
  });

  it('英語オーバーレイのキーは原本に存在し、en は ja と同じ id 並びで文言が異なる', () => {
    const ja = getStageMap('ja');
    const overlay = parseYaml(BUNDLED_STAGE_OVERLAY_EN ?? '') as {
      contractorRequirements: Record<string, { text?: string }>;
    };
    const ids = new Set(ja.contractorRequirements.map((c) => c.id));
    for (const id of Object.keys(overlay.contractorRequirements)) expect(ids.has(id), id).toBe(true);
    const en = getStageMap('en');
    expect(en.contractorRequirements.map((c) => c.id)).toEqual(ja.contractorRequirements.map((c) => c.id));
    en.contractorRequirements.forEach((c, i) => expect(c.text).not.toBe(ja.contractorRequirements[i].text));
    expect(en.stageLabels.design).toBe('Design');
  });
});

const node = (id: string, seq: number, type: string): DiagramNode =>
  ({ id, seq, type, x: 0, y: 0, label: id }) as unknown as DiagramNode;
const threat = (id: string, nodeId: string, canonicalId: string | undefined, extra: Partial<ThreatView> = {}): ThreatView => ({
  id,
  nodeId,
  subject: { kind: 'node', id: nodeId },
  framework: 'STRIDE',
  category: 'Tampering',
  severity: 'High',
  description: '説明です。',
  origin: 'detected',
  name: id,
  canonicalId,
  mitigation: '[Foundation] 基本策。 [Enterprise] 強化策。',
  mitigationTiers: { foundation: '基本策。', enterprise: '強化策。' },
  ...extra,
});

function input(threats: ThreatView[]): RequirementsInput {
  return {
    nodes: [node('api', 1, 'BACKEND_API'), node('db', 2, 'DATABASE')],
    edges: [],
    threats,
    projectMeta: { ...EMPTY_PROJECT_META, systemName: 'Demo' },
    layer: 'L1',
  };
}

describe('buildRequirements', () => {
  it('同じ canonicalId はノードをまたいで 1 行に集約され、段階ごとに行が分かれる', () => {
    const list = buildRequirements(
      input([threat('t1', 'api', 'web-form-input-injection'), threat('t2', 'db', 'web-form-input-injection')]),
      NOW,
      'ja',
    );
    expect(list.generatedAt).toBe('2026-11-07');
    expect(list.requirements.map((r) => [r.id, r.tier])).toEqual([
      ['REQ-001', 'Foundation'],
      ['REQ-002', 'Enterprise'],
    ]);
    expect(list.requirements[0].targets.map((t) => t.id)).toEqual(['C1', 'C2']);
    expect(list.requirements[0].text).toBe('基本策。');
    // マップに載る canonicalId は実装・検証、載らないものは既定（設計・検証）
    expect(list.requirements[0].stages).toEqual(['implementation', 'verification']);
  });

  it('マップに無い canonicalId は既定の工程になる。重大度の高い順に並ぶ', () => {
    const list = buildRequirements(
      input([
        threat('low', 'api', 'zzz-unknown', { severity: 'Low' }),
        threat('crit', 'db', 'account-review-gap', { severity: 'Critical' }),
      ]),
      NOW,
      'ja',
    );
    expect(list.requirements[0].maxSeverity).toBe('Critical');
    expect(list.requirements[0].stages).toEqual(['operation']);
    expect(list.requirements.at(-1)?.stages).toEqual(['design', 'verification']);
  });

  it('誤検知は除き、リスク受容は残して accepted にする', () => {
    const list = buildRequirements(
      input([
        threat('fp', 'api', 'a-x', { suppression: { status: 'false-positive', note: '', at: 0 } }),
        threat('acc', 'db', 'b-x', { suppression: { status: 'accepted', note: '費用対効果', at: 0 } }),
      ]),
      NOW,
      'ja',
    );
    expect(list.requirements.every((r) => r.threats.includes('acc'))).toBe(true);
    expect(list.requirements[0].accepted).toBe(true);
    expect(list.requirements[0].acceptedNotes).toEqual(['費用対効果']);
    expect(requirementsToMarkdown(list)).toContain('費用対効果');
  });

  it('NIST CSF の参照だけを拾い、緩和策に段階が無ければ Foundation として扱う', () => {
    const list = buildRequirements(
      input([
        threat('t', 'api', 'c-x', {
          mitigationTiers: undefined,
          mitigation: '段階なしの緩和策。',
          complianceRefs: [
            { standard: 'nist-csf-2.0', ref: 'PR.AA-05' },
            { standard: 'iso-27001', ref: 'A.8' },
          ],
        }),
      ]),
      NOW,
      'ja',
    );
    expect(list.requirements).toHaveLength(1);
    expect(list.requirements[0].tier).toBe('Foundation');
    expect(list.requirements[0].text).toBe('段階なしの緩和策。');
    expect(list.requirements[0].csfRefs).toEqual(['PR.AA-05']);
  });

  it('委託先への要件はトリガーの脅威があるときだけ載り、該当行に contractor が付く', () => {
    const none = buildRequirements(input([threat('t', 'api', 'zzz-unknown')]), NOW, 'ja');
    expect(none.contractorRequirements).toEqual([]);
    expect(none.requirements.every((r) => !r.contractor)).toBe(true);

    const hit = buildRequirements(input([threat('t', 'api', 'known-vulnerability-unpatched')]), NOW, 'en');
    expect(hit.contractorRequirements.map((c) => c.id)).toEqual(['sbom-submission', 'vulnerability-test-results']);
    expect(hit.contractorRequirements[0].text).toMatch(/SBOM/);
    expect(hit.requirements.every((r) => r.contractor)).toBe(true);
  });

  it('出力: Markdown / CSV / JSON', () => {
    const list = buildRequirements(input([threat('t', 'api', 'known-vulnerability-unpatched')]), NOW, 'ja');
    const md = requirementsToMarkdown(list);
    expect(md).toContain('たたき台');
    expect(md).toContain('REQ-001');
    expect(md).toContain('委託先へ求める要件の例');
    const csv = requirementsToCsv(list);
    expect(csv.split('\r\n')[0]).toContain('要件ID');
    expect(csv).toContain('REQ-002');
    expect(JSON.parse(requirementsToJson(list)).requirements).toHaveLength(2);
  });
});
