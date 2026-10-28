import type { DiagramEdge, DiagramNode, ThreatView } from '../../core/model/types';
import { isSuppressed } from '../../core/model/types';
import { effectiveSeverity } from '../../core/model/risk';
import { formatElementalId } from '../../core/model/elementalId';
import { crossedBoundaries, resolveNodeBoundaries } from '../../core/canvas/boundaryCrossing';
import { getComponentRegistry } from '../../component-library/defaultRegistry';
import { BRANDING } from '../../core/branding';
import type { BuildThreatReportInput } from '../export/threatReport';
import type { Locale } from '../../i18n';
import { version as APP_VERSION } from '../../../package.json';

/**
 * 脅威モデル（構成図）から、G7 Cybersecurity WG「Software Bill of Materials for AI — Minimum Elements」
 * （BSI・ACN・ANSSI・CSE・CISA・NCSC・NCO、2026）の 7 クラスタに沿った SBOM for AI を、
 * CycloneDX 1.7（https://cyclonedx.org/docs/1.7/json/）の BOM オブジェクトとして作る純粋関数。
 *
 * 対応（docs/plan.md §2.101）：
 * - Metadata               → metadata（timestamp・lifecycles=design・tools・authors）
 * - System level           → metadata.component・components・services[].data[]（データフロー）・dependencies
 * - Models                 → components[type=machine-learning-model]＋最小の modelCard
 * - Datasets               → components[type=data]＋data[]（sensitiveData）
 * - Infrastructure software → PACKAGE_DEPENDENCIES のインベントリ → components[type=library]（purl）
 * - Security               → declarations.claims（実装済みの対策）・エッジの認証／暗号／越境
 * - KPI                    → 出さない（図に無い）
 *
 * 図に無い G7 の要素は空欄にせず、要素ごとに unknown として properties に記録し、compositions を
 * incomplete にする。G7 文書（§2.1 Metadata・§2.3 Models）が「提供元が情報を持たない場合、SBOM の作成者は
 * その情報が unknown であることを示す」「実行ファイルにアクセスできない場合、ハッシュ値は unknown とする」と
 * 求めているため（"the SBOM author should indicate that the information is unknown"）。
 *
 * 秘密情報：env インベントリ（変数名・値の種類・長さ）は出力しない。依存パッケージのインベントリだけを使う。
 */

type Json = Record<string, unknown>;
interface Prop {
  name: string;
  value: string;
}

export interface SbomForAiOptions {
  /** 未抑制の脅威を vulnerabilities[] に載せる。既定は載せない（実装済みの対策だけ）。 */
  includeThreats: boolean;
  /** metadata.authors に載せる作成者名（指定時のみ）。 */
  author?: string;
  /** ISO 8601。呼び出し側が現在時刻を渡す（純粋関数を保つ）。 */
  timestamp: string;
  /** `urn:uuid:…`。呼び出し側が生成して渡す。 */
  serialNumber: string;
  /** 型ラベル（無名ノードの名前）の言語。 */
  locale: Locale;
}

const NS = 'cyberriskscape:';
const UNKNOWN_PROP = `${NS}sbom-for-ai:unknown`;
const SYSTEM_REF = 'system';

/** G7 のモデルを表す型（コンポーネントライブラリの AI カテゴリのうち推論モデル）。値は入力／出力の形式。 */
const MODEL_TYPES: Record<string, { inputs: string[]; outputs: string[] }> = {
  LLM: { inputs: ['text'], outputs: ['text'] },
  STT: { inputs: ['audio'], outputs: ['text'] },
  TTS: { inputs: ['text'], outputs: ['audio'] },
  STS: { inputs: ['audio'], outputs: ['audio'] },
};

/** データを保管する型（DOCUMENTS カテゴリのデータ資産はカテゴリで判定する）。 */
const DATA_STORE_TYPES = new Set([
  'DB', 'DATABASE', 'STORAGE', 'FILE_SERVER', 'BACKUP_STORAGE', 'IMMUTABLE_BACKUP', 'DATA_STORE', 'MEMORY_STORE',
]);

/** 外部のサービスとして services に出す型（加えて、第三者所有・Internet 境界内のノード）。 */
const SERVICE_TYPES = new Set(['SAAS', 'IAAS', 'PAAS', 'SHADOW', 'TOOL', 'EXTERNAL_ENTITY', 'PACKAGE_REGISTRY']);

/** Internet 境界内でもサービスにしない（人・端末・データ）カテゴリ。ATTACKER は出力から除く。 */
const NON_SERVICE_CATEGORIES = new Set(['USERS_DEVICES', 'DOCUMENTS']);

/** 端末として components[type=device] に出す型。 */
const DEVICE_TYPES = new Set(['PC', 'SMARTPHONE', 'IOT', 'MULTIFUNCTION_PRINTER']);

/** sensitiveData に名前を載せるデータ資産の型。 */
const SENSITIVE_TYPES = new Set(['PERSONAL_INFO', 'CONFIDENTIAL_INFO', 'CREDENTIAL', 'VOICE_RECORDING']);

/** componentData.type（既定は dataset）。 */
const DATA_KIND: Record<string, string> = { SOURCE_CODE: 'source-code', API_SPEC: 'definition' };

const MODEL_UNKNOWN = [
  'Model version', 'Model producer', 'Model timestamp', 'Model hash algorithm', 'Model hash value',
  'Model license', 'Model training properties', 'Model properties', 'Model external references',
];
const DATASET_UNKNOWN = [
  'Dataset identifier', 'Dataset hash', 'Dataset license', 'Dataset provenance', 'Dataset statistical properties',
];
const SYSTEM_UNKNOWN = ['System producer', 'System version', 'System timestamp'];

const ref = (id: string) => `node:${id}`;

/** BOM-Link の URL 断片（bom-ref）に使えない文字をパーセントエンコードする。 */
const bomLink = (serialNumber: string, bomRef: string) =>
  `urn:cdx:${serialNumber.replace(/^urn:uuid:/, '')}/1#${bomRef.replace(/[^A-Za-z0-9:._~-]/g, (c) => encodeURIComponent(c))}`;

/** purl の版を付けてよい「固定された版」か。範囲指定（^ ~ >= * 等）は false。 */
function isExactVersion(version: string, pinned: boolean | undefined): boolean {
  return pinned !== false && /^\d[0-9A-Za-z.+_!-]*$/.test(version);
}

function purlOf(kind: 'npm' | 'pypi', name: string, version?: string): string {
  const v = version ? `@${encodeURIComponent(version)}` : '';
  if (kind === 'npm') {
    const n = name.startsWith('@') ? `%40${name.slice(1)}` : name;
    return `pkg:npm/${n}${v}`;
  }
  return `pkg:pypi/${name.toLowerCase().replace(/_/g, '-')}${v}`;
}

export function buildSbomForAi(project: BuildThreatReportInput, opts: SbomForAiOptions): Json {
  const registry = getComponentRegistry(opts.locale);
  const { nodes, edges, boundaries, threats, projectMeta } = project;

  const categoryOf = (n: DiagramNode) => registry.get(n.type)?.category;
  const typeLabel = (n: DiagramNode) => registry.get(n.type)?.label ?? n.type;
  const nameOf = (n: DiagramNode) => n.label?.trim() || typeLabel(n);
  const eid = (n: DiagramNode) => (n.seq != null ? formatElementalId('node', n.seq) : n.id);

  // 攻撃者（モデル化した敵対者）はシステムの構成要素ではないので出さない。
  const members = nodes.filter((n) => categoryOf(n) !== 'ATTACKER');
  const memberIds = new Set(members.map((n) => n.id));
  const owning = resolveNodeBoundaries(members, boundaries);
  const zoneName = (nodeId: string) => {
    const b = owning.get(nodeId)?.[0];
    return b ? `${formatElementalId('boundary', b.seq ?? 0)} (${b.trustLevel})` : undefined;
  };
  const inInternetBoundary = (nodeId: string) => owning.get(nodeId)?.[0]?.trustLevel === 'Internet';

  type Kind = 'model' | 'data' | 'service' | 'device' | 'application';
  const kindOf = (n: DiagramNode): Kind => {
    if (MODEL_TYPES[n.type]) return 'model';
    if (DATA_STORE_TYPES.has(n.type) || categoryOf(n) === 'DOCUMENTS') return 'data';
    if (DEVICE_TYPES.has(n.type)) return 'device';
    if (SERVICE_TYPES.has(n.type) || n.cloudOwnership === 'ThirdParty') return 'service';
    if (inInternetBoundary(n.id) && !NON_SERVICE_CATEGORIES.has(categoryOf(n) ?? '')) return 'service';
    return 'application';
  };

  const liveEdges = edges.filter((e) => memberIds.has(e.source) && memberIds.has(e.target));
  const crosses = (e: DiagramEdge) =>
    crossedBoundaries(owning.get(e.source) ?? [], owning.get(e.target) ?? []).length > 0;
  const edgesOf = (nodeId: string) => liveEdges.filter((e) => e.source === nodeId || e.target === nodeId);
  const edgeName = (e: DiagramEdge) => (e.seq != null ? formatElementalId('edge', e.seq) : e.id);

  const unknownProp = (elements: string[]): Prop => ({ name: UNKNOWN_PROP, value: elements.join(', ') });

  /** ノード共通の properties（型・元の ID・信頼ゾーン・接続するエッジの認証／暗号／越境・内包元）。 */
  const commonProps = (n: DiagramNode): Prop[] => {
    const props: Prop[] = [
      { name: `${NS}node-id`, value: eid(n) },
      { name: `${NS}component-type`, value: n.type },
    ];
    const zone = zoneName(n.id);
    if (zone) props.push({ name: `${NS}trust-zone`, value: zone });
    if (n.parentId && memberIds.has(n.parentId)) props.push({ name: `${NS}contained-in`, value: ref(n.parentId) });
    for (const e of edgesOf(n.id)) {
      const peer = e.source === n.id ? e.target : e.source;
      props.push({
        name: `${NS}data-flow`,
        value: `${edgeName(e)} peer=${ref(peer)} direction=${e.source === n.id ? 'source' : 'target'} flow=${e.dataFlow ?? 'unknown'} auth=${e.auth} encryption=${e.encryption} network=${e.network} crosses-trust-boundary=${crosses(e)}`,
      });
    }
    return props;
  };

  const components: Json[] = [];
  const services: Json[] = [];
  const dependencies = new Map<string, Set<string>>();
  const dep = (from: string, to?: string) => {
    const set = dependencies.get(from) ?? new Set<string>();
    if (to) set.add(to);
    dependencies.set(from, set);
  };
  const unknownRefs: string[] = [];

  for (const n of members) {
    const kind = kindOf(n);
    const bomRef = ref(n.id);
    const base = { 'bom-ref': bomRef, name: nameOf(n), ...(n.description?.trim() ? { description: n.description.trim() } : {}) };
    dep(bomRef);

    if (kind === 'service') {
      const myEdges = edgesOf(n.id);
      const service: Json = { ...base };
      const zone = zoneName(n.id);
      if (zone) service.trustZone = zone;
      if (myEdges.length > 0) {
        service.authenticated = myEdges.every((e) => e.auth !== 'None');
        service['x-trust-boundary'] = myEdges.some(crosses);
        service.data = myEdges.map((e) => serviceData(e, n.id));
      }
      service.properties = commonProps(n);
      services.push(service);
      continue;
    }

    const component: Json = { type: kind === 'device' ? 'device' : 'application', ...base };
    const props = commonProps(n);
    if (kind === 'model') {
      const io = MODEL_TYPES[n.type];
      component.type = 'machine-learning-model';
      component.modelCard = {
        modelParameters: {
          inputs: io.inputs.map((format) => ({ format })),
          outputs: io.outputs.map((format) => ({ format })),
        },
      };
      props.push(unknownProp(MODEL_UNKNOWN));
      unknownRefs.push(bomRef);
    } else if (kind === 'data') {
      component.type = 'data';
      const sensitive = [
        ...(SENSITIVE_TYPES.has(n.type) ? [nameOf(n)] : []),
        ...members.filter((c) => c.parentId === n.id && SENSITIVE_TYPES.has(c.type)).map(nameOf),
      ];
      component.data = [
        {
          type: DATA_KIND[n.type] ?? 'dataset',
          name: nameOf(n),
          ...(sensitive.length > 0 ? { sensitiveData: sensitive } : {}),
        },
      ];
      props.push(unknownProp(DATASET_UNKNOWN));
      unknownRefs.push(bomRef);
    }
    component.properties = props;
    components.push(component);

    // Infrastructure software：依存パッケージのインベントリ（env は出さない）。
    const inv = n.inventory;
    if (inv && (inv.kind === 'npm' || inv.kind === 'pypi')) {
      const seen = new Set<string>();
      for (const item of inv.items) {
        const exact = !!item.version && isExactVersion(item.version, item.pinned);
        const libRef = `lib:${n.id}:${item.name}@${item.version ?? ''}`;
        if (seen.has(libRef)) continue;
        seen.add(libRef);
        const lib: Json = {
          type: 'library',
          'bom-ref': libRef,
          name: item.name,
          ...(item.version ? { version: item.version } : {}),
          ...(item.dev ? { scope: 'optional' } : {}),
          purl: purlOf(inv.kind, item.name, exact ? item.version : undefined),
        };
        if (item.hasInstallScript) lib.properties = [{ name: `${NS}has-install-script`, value: 'true' }];
        components.push(lib);
        dep(bomRef, libRef);
        dep(libRef);
      }
    }
  }

  function serviceData(e: DiagramEdge, serviceId: string): Json {
    // dataFlow は source→target 基準。サービスから見た向きに直す。未設定は unknown。
    const from = e.dataFlow === 'inbound' ? e.target : e.source;
    const to = from === e.source ? e.target : e.source;
    let flow = 'unknown';
    if (e.dataFlow === 'bidirectional') flow = 'bi-directional';
    else if (e.dataFlow) flow = to === serviceId ? 'inbound' : 'outbound';
    const peerId = e.source === serviceId ? e.target : e.source;
    return {
      flow,
      // エッジにデータ分類の属性は無い。
      classification: 'unknown',
      name: e.dataFlowName?.trim() || edgeName(e),
      description: `auth=${e.auth}; encryption=${e.encryption}; network=${e.network}; crosses-trust-boundary=${crosses(e)}; peer=${ref(peerId)}`,
      // 向きが未設定のときは、どちらが送り手か分からないので source / destination を書かない。
      ...(e.dataFlow
        ? { source: [bomLink(opts.serialNumber, ref(from))], destination: [bomLink(opts.serialNumber, ref(to))] }
        : {}),
    };
  }

  // データフローは dependencies にも出す（サービスを介さない内部ノード間のフローは、CycloneDX では
  // これと各コンポーネントの properties（cyberriskscape:data-flow）でしか表せない）。
  for (const e of liveEdges) dep(ref(e.source), ref(e.target));
  dep(SYSTEM_REF, undefined);
  for (const n of members) if (!n.parentId || !memberIds.has(n.parentId)) dep(SYSTEM_REF, ref(n.id));

  // Security：実装済みの対策を declarations.claims に。
  const subjectRefs = (t: ThreatView): string[] => {
    const s = t.subject;
    if (s?.kind === 'edge') {
      const e = liveEdges.find((x) => x.id === s.id);
      return e ? [ref(e.source), ref(e.target)] : [];
    }
    const id = s?.kind === 'node' ? s.id : t.nodeId;
    return id && memberIds.has(id) ? [ref(id)] : [];
  };
  const evidence: Json[] = [];
  const claims: Json[] = [];
  for (const t of threats) {
    if (t.controlStatus?.status !== 'implemented') continue;
    const target = subjectRefs(t)[0];
    if (!target) continue;
    const title = t.name ?? t.category;
    evidence.push({
      'bom-ref': `evidence:${t.id}`,
      propertyName: title,
      ...(t.controlStatus.note ? { description: t.controlStatus.note } : {}),
    });
    const compliance = (t.complianceRefs ?? []).map((c) => `${c.standard} ${c.ref}`);
    claims.push({
      'bom-ref': `claim:${t.id}`,
      target,
      predicate: `Control implemented against threat "${title}"${t.ruleId ? ` (${t.ruleId})` : ''}`,
      mitigationStrategies: [`evidence:${t.id}`],
      ...(compliance.length > 0 ? { reasoning: `Compliance references: ${compliance.join('; ')}` } : {}),
    });
  }

  // 未対策の脅威（任意）。抑制済み（受容・誤検知）と、実装済みの対策がある脅威は出さない。
  const vulnerabilities: Json[] = [];
  if (opts.includeThreats) {
    for (const t of threats) {
      if (isSuppressed(t) || t.controlStatus?.status === 'implemented') continue;
      const affects = subjectRefs(t).map((r) => ({ ref: r }));
      const props: Prop[] = [
        { name: `${NS}category`, value: t.category },
        { name: `${NS}framework`, value: t.framework },
        ...(t.subject?.kind === 'edge' ? [{ name: `${NS}edge`, value: t.subject.id }] : []),
        ...(t.complianceRefs ?? []).map((c) => ({ name: `${NS}compliance`, value: `${c.standard} ${c.ref}` })),
      ];
      vulnerabilities.push({
        'bom-ref': `vuln:${t.id}`,
        id: t.ruleId ?? t.id,
        source: { name: BRANDING.name },
        ratings: [{ source: { name: BRANDING.name }, severity: effectiveSeverity(t).toLowerCase() }],
        description: t.name ? `${t.name}: ${t.description}` : t.description,
        ...(affects.length > 0 ? { affects } : {}),
        properties: props,
      });
    }
  }

  const system: Json = {
    type: 'application',
    'bom-ref': SYSTEM_REF,
    name: projectMeta.systemName.trim() || projectMeta.name.trim() || 'unknown',
    ...(projectMeta.purpose.trim() ? { description: projectMeta.purpose.trim() } : {}),
    properties: [unknownProp(SYSTEM_UNKNOWN)],
  };

  const bom: Json = {
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    serialNumber: opts.serialNumber,
    version: 1,
    metadata: {
      timestamp: opts.timestamp,
      lifecycles: [{ phase: 'design' }],
      tools: { components: [{ type: 'application', name: BRANDING.name, version: APP_VERSION }] },
      ...(opts.author?.trim() ? { authors: [{ name: opts.author.trim() }] } : {}),
      component: system,
      properties: [
        { name: `${NS}sbom-for-ai:source`, value: 'threat model (design-time)' },
        { name: `${NS}sbom-for-ai:not-included`, value: 'Key Performance Indicators cluster; signature' },
      ],
    },
    components,
    ...(services.length > 0 ? { services } : {}),
    dependencies: [...dependencies].map(([r, to]) => ({ ref: r, ...(to.size > 0 ? { dependsOn: [...to] } : {}) })),
    // 図に無い G7 要素があるため完全ではない。
    compositions: [{ aggregate: 'incomplete', assemblies: [SYSTEM_REF, ...unknownRefs] }],
  };
  if (claims.length > 0) bom.declarations = { claims, evidence };
  if (vulnerabilities.length > 0) bom.vulnerabilities = vulnerabilities;
  return bom;
}
