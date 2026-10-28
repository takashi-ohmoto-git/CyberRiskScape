import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { buildSbomForAi, type SbomForAiOptions } from './buildSbomForAi';
import { analyzeProject } from '../../cli/analyze';
import type { BuildThreatReportInput } from '../export/threatReport';
import {
  EMPTY_PROJECT_META,
  type DiagramBoundary,
  type DiagramEdge,
  type DiagramNode,
  type ThreatView,
} from '../../core/model/types';

/**
 * 出力が CycloneDX 1.7 の公式スキーマに適合することを ajv（draft-07）で検証する。
 * スキーマは __fixtures__/ に置いた公式の写し（出典・取得日は __fixtures__/README.md）。
 */
const FIXTURES = new URL('./__fixtures__/', import.meta.url);
const load = (name: string) => JSON.parse(readFileSync(new URL(name, FIXTURES), 'utf-8'));

function validator() {
  const ajv = new Ajv({ strict: false, allErrors: true });
  addFormats(ajv);
  // ajv-formats に iri-reference は無い。空白を含まない文字列だけ確認する（BOM-Link はスキーマの pattern でも検証される）。
  ajv.addFormat('iri-reference', /^\S*$/);
  ajv.addSchema(load('spdx.schema.json'));
  ajv.addSchema(load('jsf-0.82.schema.json'));
  ajv.addSchema(load('cryptography-defs.schema.json'));
  return ajv.compile(load('bom-1.7.schema.json'));
}
const validate = validator();

function expectValid(bom: unknown) {
  const ok = validate(bom);
  expect(ok, JSON.stringify(validate.errors?.slice(0, 5), null, 2)).toBe(true);
}

const SERIAL = 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79';
const OPTS: SbomForAiOptions = {
  includeThreats: false,
  timestamp: '2026-10-29T00:00:00.000Z',
  serialNumber: SERIAL,
  locale: 'en',
};

const node = (id: string, type: string, extra: Partial<DiagramNode> = {}): DiagramNode =>
  ({ id, type, x: 0, y: 0, ...extra }) as DiagramNode;
const edge = (id: string, source: string, target: string, extra: Partial<DiagramEdge> = {}): DiagramEdge => ({
  id, source, target, auth: 'None', network: 'VPC', encryption: 'Plain', ...extra,
});
const threat = (id: string, extra: Partial<ThreatView> = {}): ThreatView =>
  ({
    id, ruleId: `rule-${id}`, origin: 'detected', nodeId: 'llm', framework: 'AI', category: 'Cat',
    name: `Threat ${id}`, severity: 'High', description: `desc ${id}`, subject: { kind: 'node', id: 'llm' },
    ...extra,
  }) as ThreatView;

const ENV_NAMES = ['AWS_SECRET_ACCESS_KEY', 'DATABASE_PASSWORD'];

function sampleInput(threats: ThreatView[] = []): BuildThreatReportInput {
  const nodes: DiagramNode[] = [
    node('app', 'FRONT_END_SERVER', { seq: 1, label: 'Web App', description: 'frontend' }),
    node('llm', 'LLM', { seq: 2, label: 'Claude' }),
    node('stt', 'STT', { seq: 3 }),
    node('db', 'DB', { seq: 4, label: 'Vector DB' }),
    node('pii', 'PERSONAL_INFO', { seq: 5, label: 'Customer PII', parentId: 'db' }),
    node('saas', 'SAAS', { seq: 6, label: 'CRM SaaS' }),
    node('ext', 'FRONT_END_SERVER', { seq: 7, label: 'Partner API' }),
    node('attacker', 'THREAT_ACTOR', { seq: 8 }),
    node('env', 'CREDENTIAL', {
      seq: 9,
      label: '.env',
      inventory: {
        kind: 'env', source: '.env', collectedAt: '2026-10-29T00:00:00Z', template: false,
        items: ENV_NAMES.map((name) => ({ name, valueKind: 'secret-like' as const, length: 40 })),
      },
    }),
    node('pkgs', 'PACKAGE_DEPENDENCIES', {
      seq: 10,
      label: 'package.json',
      inventory: {
        kind: 'npm', source: 'package.json', collectedAt: '2026-10-29T00:00:00Z',
        items: [
          { name: 'react', version: '18.3.1', pinned: true },
          { name: '@scope/pkg', version: '1.2.3', pinned: true, dev: true, hasInstallScript: true },
          { name: 'left-pad', version: '^1.0.0', pinned: false },
          { name: 'react', version: '18.3.1', pinned: true },
        ],
      },
    }),
    node('py', 'PACKAGE_DEPENDENCIES', {
      seq: 11,
      inventory: {
        kind: 'pypi', source: 'requirements.lock', collectedAt: '2026-10-29T00:00:00Z',
        items: [{ name: 'Fast_API', version: '0.1.0', pinned: true }],
      },
    }),
  ];
  const edges: DiagramEdge[] = [
    edge('e1', 'app', 'llm', { seq: 1, auth: 'Token', encryption: 'TLS', dataFlow: 'outbound' }),
    edge('e2', 'llm', 'db', { seq: 2, dataFlow: 'bidirectional' }),
    edge('e3', 'app', 'saas', { seq: 3, auth: 'ApiKey', encryption: 'TLS', dataFlow: 'outbound', dataFlowName: 'orders' }),
    edge('e4', 'saas', 'app', { seq: 4, dataFlow: 'inbound' }),
    edge('e5', 'app', 'ext', { seq: 5 }),
    edge('e6', 'attacker', 'app', { seq: 6 }),
    edge('e7', 'app', 'pkgs', { seq: 7 }),
  ];
  const boundaries: DiagramBoundary[] = [
    { id: 'z1', seq: 1, type: 'RECT', x: 900, y: 900, width: 400, height: 400, trustLevel: 'Internet' },
  ];
  nodes[6].x = 1050; // ext は Internet 境界内
  nodes[6].y = 1050;
  return { threats, nodes, edges, boundaries, projectMeta: { ...EMPTY_PROJECT_META, systemName: 'Shop', purpose: 'sell' }, framework: 'ALL', layer: 'L1' };
}

type Obj = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

describe('buildSbomForAi', () => {
  it('（検証器の健全性）不正な BOM は弾く', () => {
    expect(validate({ bomFormat: 'CycloneDX', specVersion: '1.7', components: [{ type: 'bad', name: 'x' }] })).toBe(false);
  });

  it('公式スキーマ（CycloneDX 1.7）に適合する', () => {
    expectValid(buildSbomForAi(sampleInput(), OPTS));
    expectValid(buildSbomForAi(sampleInput([threat('a'), threat('b', { controlStatus: { status: 'implemented', note: 'WAF', at: 0 } })]), { ...OPTS, includeThreats: true, author: 'Taro' }));
  });

  it('既存フィクスチャ（analyzeProject の出力）でもスキーマに適合する', () => {
    const raw = JSON.parse(readFileSync('src/cli/__fixtures__/sample-project.json', 'utf-8'));
    const [r] = analyzeProject(raw, { locale: 'en' });
    expectValid(buildSbomForAi(r.input, { ...OPTS, includeThreats: true }));
  });

  it('メタデータ：1.7・design・ツール（branding と package.json の版）・作成者は指定時のみ', () => {
    const bom = buildSbomForAi(sampleInput(), OPTS) as Obj;
    expect(bom).toMatchObject({ bomFormat: 'CycloneDX', specVersion: '1.7', serialNumber: SERIAL, version: 1 });
    expect(bom.metadata.lifecycles).toEqual([{ phase: 'design' }]);
    expect(bom.metadata.timestamp).toBe(OPTS.timestamp);
    const tool = bom.metadata.tools.components[0];
    expect(tool.name).toBe('CyberRiskScape');
    expect(tool.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(bom.metadata.authors).toBeUndefined();
    expect(bom.metadata.component).toMatchObject({ type: 'application', name: 'Shop', description: 'sell' });
    expect(bom.metadata.component.properties[0].value).toContain('System version');
    const named = buildSbomForAi(sampleInput(), { ...OPTS, author: 'Taro' }) as Obj;
    expect(named.metadata.authors).toEqual([{ name: 'Taro' }]);
  });

  it('型の対応：モデル・データ・サービス・アプリ（攻撃者は除く）', () => {
    const bom = buildSbomForAi(sampleInput(), OPTS) as Obj;
    const byRef = (r: string) => bom.components.find((c: Obj) => c['bom-ref'] === r);
    expect(byRef('node:llm')).toMatchObject({ type: 'machine-learning-model', name: 'Claude' });
    expect(byRef('node:llm').modelCard.modelParameters.inputs).toEqual([{ format: 'text' }]);
    expect(byRef('node:stt').modelCard.modelParameters.inputs).toEqual([{ format: 'audio' }]);
    expect(byRef('node:db')).toMatchObject({ type: 'data' });
    expect(byRef('node:db').data[0]).toMatchObject({ type: 'dataset', sensitiveData: ['Customer PII'] });
    expect(byRef('node:pii')).toMatchObject({ type: 'data' });
    expect(byRef('node:app')).toMatchObject({ type: 'application', description: 'frontend' });
    expect(byRef('node:attacker')).toBeUndefined();
    const withPc = sampleInput();
    withPc.nodes.push(node('pc', 'PC', { seq: 99, label: 'Laptop' }));
    const pc = (buildSbomForAi(withPc, OPTS) as Obj).components.find((c: Obj) => c['bom-ref'] === 'node:pc');
    expect(pc).toMatchObject({ type: 'device', name: 'Laptop' });
    const svc = bom.services.map((s: Obj) => s['bom-ref']);
    expect(svc).toEqual(expect.arrayContaining(['node:saas', 'node:ext']));
    expect(svc).not.toContain('node:app');
  });

  it('エッジ：サービスの data flow（向き・分類・BOM-Link）と、内部ノード間は dependencies / properties', () => {
    const bom = buildSbomForAi(sampleInput(), OPTS) as Obj;
    const saas = bom.services.find((s: Obj) => s['bom-ref'] === 'node:saas');
    expect(saas.authenticated).toBe(false); // e4 は auth None
    const orders = saas.data.find((d: Obj) => d.name === 'orders');
    expect(orders).toMatchObject({ flow: 'inbound', classification: 'unknown' });
    expect(orders.source).toEqual([`urn:cdx:${SERIAL.slice(9)}/1#node:app`]);
    expect(orders.destination).toEqual([`urn:cdx:${SERIAL.slice(9)}/1#node:saas`]);
    // e4 は saas→app で dataFlow=inbound（データは target→source = app→saas）。saas から見ると受け取る側。
    const e4 = saas.data.find((d: Obj) => d.name === 'DF4');
    expect(e4.flow).toBe('inbound');
    expect(e4.source).toEqual([`urn:cdx:${SERIAL.slice(9)}/1#node:app`]);
    const ext = bom.services.find((s: Obj) => s['bom-ref'] === 'node:ext');
    expect(ext.data[0].flow).toBe('unknown');
    expect(ext.data[0].source).toBeUndefined();
    expect(ext['x-trust-boundary']).toBe(true);
    const llm = bom.components.find((c: Obj) => c['bom-ref'] === 'node:llm');
    const flows = llm.properties.filter((p: Obj) => p.name === 'cyberriskscape:data-flow').map((p: Obj) => p.value);
    expect(flows.some((v: string) => v.startsWith('DF2 peer=node:db') && v.includes('flow=bidirectional'))).toBe(true);
    const dep = (r: string) => bom.dependencies.find((d: Obj) => d.ref === r);
    expect(dep('node:llm').dependsOn).toContain('node:db');
    expect(bom.dependencies.some((d: Obj) => d.ref === 'node:attacker')).toBe(false);
  });

  it('インベントリ：library と purl（scoped は %40・範囲指定は版なし・重複排除）、dev は optional', () => {
    const bom = buildSbomForAi(sampleInput(), OPTS) as Obj;
    const libs = bom.components.filter((c: Obj) => c.type === 'library');
    const purls = libs.map((l: Obj) => l.purl);
    expect(purls).toEqual(expect.arrayContaining(['pkg:npm/react@18.3.1', 'pkg:npm/%40scope/pkg@1.2.3', 'pkg:npm/left-pad', 'pkg:pypi/fast-api@0.1.0']));
    expect(purls.filter((p: string) => p === 'pkg:npm/react@18.3.1')).toHaveLength(1);
    expect(libs.find((l: Obj) => l.name === 'left-pad').version).toBe('^1.0.0');
    expect(libs.find((l: Obj) => l.name === '@scope/pkg')).toMatchObject({ scope: 'optional' });
    const dep = bom.dependencies.find((d: Obj) => d.ref === 'node:pkgs');
    expect(dep.dependsOn).toHaveLength(3);
    expect(dep.dependsOn.every((r: string) => r.startsWith('lib:'))).toBe(true);
  });

  it('env インベントリ（変数名など）は出力に含まれない', () => {
    const text = JSON.stringify(buildSbomForAi(sampleInput(), { ...OPTS, includeThreats: true }));
    for (const name of ENV_NAMES) expect(text).not.toContain(name);
    expect(text).not.toContain('secret-like');
  });

  it('includeThreats：既定は vulnerabilities なし。on で未抑制だけ、抑制済み・実装済みは出ない', () => {
    const threats = [
      threat('open', { severity: 'Critical' }),
      threat('acc', { suppression: { status: 'accepted', at: 0 } }),
      threat('fp', { suppression: { status: 'false-positive', at: 0 } }),
      threat('red', { suppression: { status: 'reduce', at: 0 } }),
      threat('impl', { controlStatus: { status: 'implemented', note: 'done', at: 0 } }),
    ];
    const off = buildSbomForAi(sampleInput(threats), OPTS) as Obj;
    expect(off.vulnerabilities).toBeUndefined();
    const on = buildSbomForAi(sampleInput(threats), { ...OPTS, includeThreats: true }) as Obj;
    const ids = on.vulnerabilities.map((v: Obj) => v.id);
    expect(ids).toEqual(['rule-open', 'rule-red']);
    expect(on.vulnerabilities[0]).toMatchObject({
      source: { name: 'CyberRiskScape' },
      ratings: [{ severity: 'critical' }],
      affects: [{ ref: 'node:llm' }],
    });
    expectValid(on);
  });

  it('Security：実装済みの対策は declarations.claims に（既定でも出る）、compliance は reasoning に', () => {
    const t = threat('impl', {
      controlStatus: { status: 'implemented', note: 'guardrail deployed', at: 0 },
      complianceRefs: [{ standard: 'NIST AI RMF', ref: 'MEASURE 2.7' }],
    });
    const bom = buildSbomForAi(sampleInput([t]), OPTS) as Obj;
    expect(bom.declarations.claims).toHaveLength(1);
    expect(bom.declarations.claims[0]).toMatchObject({
      target: 'node:llm',
      mitigationStrategies: ['evidence:impl'],
    });
    expect(bom.declarations.claims[0].reasoning).toContain('MEASURE 2.7');
    expect(bom.declarations.evidence[0].description).toBe('guardrail deployed');
    expectValid(bom);
  });

  it('unknown：モデル・データセット・システムの図に無い要素を記録し、compositions は incomplete', () => {
    const bom = buildSbomForAi(sampleInput(), OPTS) as Obj;
    const unknownOf = (c: Obj) => c.properties.find((p: Obj) => p.name === 'cyberriskscape:sbom-for-ai:unknown')?.value as string;
    const model = bom.components.find((c: Obj) => c['bom-ref'] === 'node:llm');
    expect(unknownOf(model)).toContain('Model hash value');
    expect(unknownOf(model)).toContain('Model version');
    const db = bom.components.find((c: Obj) => c['bom-ref'] === 'node:db');
    expect(unknownOf(db)).toContain('Dataset provenance');
    expect(bom.compositions[0].aggregate).toBe('incomplete');
    expect(bom.compositions[0].assemblies).toEqual(expect.arrayContaining(['system', 'node:llm', 'node:db']));
  });
});
