import { describe, expect, it } from 'vitest';
import { BUNDLED_ENTRY_SURFACES, evaluateEntrySurfaces, loadEntrySurfaces } from './entrySurfaces';
import { findEntryPoints } from './findEntryPoints';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';
import { PersistedLayerDataSchema } from '../persistence/schema';
import type { DiagramNode, ThreatView } from '../../core/model/types';

function node(id: string, type: string, extra: Partial<DiagramNode> = {}): DiagramNode {
  return { id, type, x: 0, y: 0, ...extra };
}

function threat(nodeId: string, canonicalId: string, extra: Partial<ThreatView> = {}): ThreatView {
  return {
    id: `${canonicalId}-${nodeId}`,
    origin: 'detected',
    nodeId,
    canonicalId,
    framework: 'STRIDE',
    category: 'c',
    severity: 'High',
    description: 'd',
    ...extra,
  } as ThreatView;
}

const api = node('api', 'BACKEND_API');
const ids = (r: ReturnType<typeof evaluateEntrySurfaces>) => r.surfaces.map((s) => s.id);

describe('evaluateEntrySurfaces', () => {
  it('脅威の canonicalId が面に載っていれば、その面と届き得る先を返す', () => {
    const r = evaluateEntrySurfaces(api, [api], [threat('api', 'web-cache-poisoning'), threat('api', 'request-race-condition')]);
    expect(ids(r)).toEqual(['cachePoisoning', 'raceCondition']);
    expect(r.outcomes).toEqual(['privesc', 'exfil']);
    expect(r.surfaces[0]).toMatchObject({ threatIds: ['web-cache-poisoning-api'], canonicalIds: ['web-cache-poisoning'] });
  });

  it('内包する子ノードの脅威も数える', () => {
    const child = node('c', 'CREDENTIAL', { parentId: 'api' });
    const r = evaluateEntrySurfaces(api, [api, child], [threat('c', 'parameter-type-confusion')]);
    expect(ids(r)).toEqual(['typeConfusion']);
  });

  it('抑制した脅威・載っていない canonicalId は数えない', () => {
    const suppressed = threat('api', 'web-cache-poisoning', { suppression: { status: 'accepted' } } as Partial<ThreatView>);
    const r = evaluateEntrySurfaces(api, [api], [suppressed, threat('api', 'no-such-canonical')]);
    expect(r).toEqual({ surfaces: [], outcomes: [] });
  });

  it.each([
    ['未入力', undefined],
    ['No', 'No' as const],
  ])('declaredBy の面は運用状況が %s なら数えない（脅威の一覧には残る）', (_label, value) => {
    const n = node('api', 'BACKEND_API', value ? { posture: { fileUpload: value } } : {});
    const t = threat('api', 'web-shell-implant');
    expect(ids(evaluateEntrySurfaces(n, [n], [t]))).toEqual([]);
  });

  it('declaredBy の面は運用状況が Yes のときだけ数える。複数の面に載る canonicalId は両方に数える', () => {
    const n = node('api', 'BACKEND_API', { posture: { fileUpload: 'Yes', deserializesInput: 'Yes' } });
    const r = evaluateEntrySurfaces(n, [n], [threat('api', 'api-server-code-execution')]);
    expect(ids(r)).toEqual(['fileUpload', 'deserialization']);
    expect(r.outcomes).toEqual(['rce']);
  });

  it('届き得る先は rce・privesc・exfil・recon の順に重複なしで返す', () => {
    const r = evaluateEntrySurfaces(api, [api], [
      threat('api', 'api-error-information-disclosure'),
      threat('api', 'http-request-smuggling'),
    ]);
    expect(r.outcomes).toEqual(['rce', 'privesc', 'exfil', 'recon']);
  });
});

describe('findEntryPoints の順位（届き得る先）', () => {
  const attacker = node('atk', 'AGENTIC_ATTACKER');

  it('弱点の数が同じなら、届き得る先の数が多い入口が先（脅威の重大度より優先）', () => {
    const a = node('a', 'FRONT_END_SERVER', { seq: 1 });
    const b = node('b', 'FRONT_END_SERVER', { seq: 2 });
    const threats = [
      threat('a', 'web-cache-poisoning', { severity: 'Critical' }),
      threat('b', 'input-canonicalization-mismatch', { severity: 'Low' }),
    ];
    const r = findEntryPoints([attacker, a, b], [], [], threats, 'atk');
    expect(r.map((c) => c.nodeId)).toEqual(['b', 'a']);
    expect(r[0].outcomes).toEqual(['rce', 'privesc', 'exfil']);
    expect(r[1].outcomes).toEqual(['exfil']);
  });

  it('届き得る先の数が同じなら、面の数が多い入口が先', () => {
    const c = node('c', 'FRONT_END_SERVER', { seq: 1 });
    const d = node('d', 'FRONT_END_SERVER', { seq: 2 });
    const threats = [
      threat('c', 'api-object-level-authorization'),
      threat('d', 'api-object-level-authorization'),
      threat('d', 'request-race-condition'),
    ];
    const r = findEntryPoints([attacker, c, d], [], [], threats, 'atk');
    expect(r.map((x) => x.nodeId)).toEqual(['d', 'c']);
    expect(r[0].surfaces).toHaveLength(2);
    expect(r[0].outcomes).toEqual(r[1].outcomes);
  });

  it('面が無い入口は surfaces・outcomes が空で、従来の順位（重大度）のまま', () => {
    const a = node('a', 'FRONT_END_SERVER', { seq: 1 });
    const b = node('b', 'FRONT_END_SERVER', { seq: 2 });
    const r = findEntryPoints([attacker, a, b], [], [], [threat('b', 'other', { severity: 'Critical' })], 'atk');
    expect(r.map((c) => c.nodeId)).toEqual(['b', 'a']);
    expect(r[0]).toMatchObject({ surfaces: [], outcomes: [] });
  });
});

describe('loadEntrySurfaces', () => {
  const y = (body: string) => `schemaVersion: 1\nsurfaces:\n${body}`;

  it('面の id の重複はエラー', () => {
    const body = '  - id: a\n    outcomes: [rce]\n    canonicalIds: [x]\n  - id: a\n    outcomes: [rce]\n    canonicalIds: [y]\n';
    expect(() => loadEntrySurfaces(y(body))).toThrow(/複数回/);
  });

  it('同じ面の中での canonicalId の重複はエラー、別の面なら同じ canonicalId を載せてよい', () => {
    expect(() => loadEntrySurfaces(y('  - id: a\n    outcomes: [rce]\n    canonicalIds: [x, x]\n'))).toThrow(/複数回/);
    const body = '  - id: a\n    outcomes: [rce]\n    canonicalIds: [x]\n  - id: b\n    outcomes: [exfil]\n    canonicalIds: [x]\n';
    expect(loadEntrySurfaces(y(body))).toHaveLength(2);
  });

  it('declaredBy が inputFeatures のフィールドでなければエラー', () => {
    const body = '  - id: a\n    outcomes: [rce]\n    canonicalIds: [x]\n    declaredBy: meteredCalls\n';
    expect(() => loadEntrySurfaces(y(body))).toThrow(/inputFeatures/);
  });

  it('届き得る先が未知の値・空ならエラー', () => {
    expect(() => loadEntrySurfaces(y('  - id: a\n    outcomes: [bogus]\n    canonicalIds: [x]\n'))).toThrow();
    expect(() => loadEntrySurfaces(y('  - id: a\n    outcomes: []\n    canonicalIds: [x]\n'))).toThrow();
  });
});

describe('同梱の入口の面の表', () => {
  it('10 の面があり、canonicalId はすべて脅威ライブラリに存在する', () => {
    const known = new Set(BUNDLED_THREAT_LIBRARY.rules.map((r) => r.canonicalId));
    const missing = BUNDLED_ENTRY_SURFACES.flatMap((s) => s.canonicalIds).filter((c) => !known.has(c));
    expect(BUNDLED_ENTRY_SURFACES).toHaveLength(10);
    expect(missing).toEqual([]);
  });

  it('明示が要る面は 3 つ（fileUpload・deserialization・preAuthBuiltinRoute）', () => {
    expect(BUNDLED_ENTRY_SURFACES.filter((s) => s.declaredBy).map((s) => s.id).sort()).toEqual([
      'deserialization',
      'fileUpload',
      'preAuthBuiltinRoute',
    ]);
  });

  it('noRateLimit: declaredBy を持たず、outcomes と canonicalIds が決めた値', () => {
    const s = BUNDLED_ENTRY_SURFACES.find((x) => x.id === 'noRateLimit');
    expect(s?.declaredBy).toBeUndefined();
    expect(s?.outcomes).toEqual(['privesc', 'exfil']);
    expect(s?.canonicalIds).toEqual(['login-credential-guessing', 'api-bulk-data-harvesting']);
  });
});

describe('保存形式の互換', () => {
  const layer = (posture?: Record<string, string>) => ({
    nodes: [{ id: 'n', type: 'BACKEND_API', x: 0, y: 0, ...(posture ? { posture } : {}) }],
    edges: [],
    boundaries: [],
  });

  it('inputFeatures の項目を持たない旧い保存データも読み込め、新しい項目も保存できる', () => {
    expect(PersistedLayerDataSchema.safeParse(layer({ patchStatus: 'Missing' })).success).toBe(true);
    expect(PersistedLayerDataSchema.safeParse(layer()).success).toBe(true);
    expect(PersistedLayerDataSchema.safeParse(layer({ fileUpload: 'Yes' })).success).toBe(true);
    expect(PersistedLayerDataSchema.safeParse(layer({ fileUpload: 'Maybe' })).success).toBe(false);
  });
});
