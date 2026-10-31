import { XMLParser } from 'fast-xml-parser';
import { z } from 'zod';

/**
 * SCAP の結果ファイル（XCCDF 1.1/1.2 の結果・ARF 1.1・OVAL 5 の結果）を、取り込みに必要な項目だけに正規化する
 * （docs/architecture.md §8.6）。純粋関数（ファイル I/O なし）。XML は信頼できない入力として扱う。
 *
 * 安全：DOCTYPE・ENTITY を含む入力は拒否し、実体の展開は無効にする。文字列は 200 文字で切る。
 * 捨てるもの：ルールの説明・修正手順・テストの詳細・収集項目（指摘に不要なため読まない）。
 */

export type ScapFormat = 'xccdf' | 'arf' | 'oval';

const TEXT_MAX = 200;
const LIST_MAX = 50000;

const Str = z.string().max(TEXT_MAX);
const IdentSchema = z.object({ system: Str, value: Str });
const XccdfFailSchema = z.object({
  idref: Str.min(1),
  severity: Str.optional(),
  title: Str.optional(),
  idents: z.array(IdentSchema).max(50),
  /** この規則の check が参照する OVAL 定義 ID。 */
  ovalRefs: z.array(Str).max(50),
});
const OvalHitSchema = z.object({
  definitionId: Str.min(1),
  class: z.enum(['vulnerability', 'patch']),
  title: Str.optional(),
  cves: z.array(Str).max(50),
  severity: Str.optional(),
});
const CountsSchema = z.object({
  pass: z.number().int().nonnegative(),
  fail: z.number().int().nonnegative(),
  error: z.number().int().nonnegative(),
  unknown: z.number().int().nonnegative(),
  other: z.number().int().nonnegative(),
});
const ScapHostSchema = z.object({
  /** 取り込み直しの置き換え単位（hostname || fqdn || 最初の IP || 'unknown-host'）。 */
  scope: Str.min(1),
  hostnames: z.array(Str).max(20),
  fqdns: z.array(Str).max(20),
  ips: z.array(Str).max(50),
  product: Str.min(1),
  productVersion: z.string().max(50).optional(),
  observedAt: Str.optional(),
  xccdfFails: z.array(XccdfFailSchema).max(LIST_MAX),
  ovalTrue: z.array(OvalHitSchema).max(LIST_MAX),
  /** OVAL のうち XCCDF の check が参照している定義 ID（ARF で二重に数えないため）。 */
  xccdfOvalRefs: z.array(Str).max(LIST_MAX),
  counts: CountsSchema,
});

export type ScapIdent = z.infer<typeof IdentSchema>;
export type XccdfFail = z.infer<typeof XccdfFailSchema>;
export type OvalHit = z.infer<typeof OvalHitSchema>;
export type ScapCounts = z.infer<typeof CountsSchema>;
export type ScapHost = z.infer<typeof ScapHostSchema>;

export type ParseScapResult = { ok: true; format: ScapFormat; hosts: ScapHost[] } | { ok: false; error: string };

// ── XML の読み取り ────────────────────────────────────────

const REPEATED = new Set([
  'rule-result',
  'Rule',
  'ident',
  'definition',
  'asset',
  'report',
  'reference',
  'ip-address',
  'fqdn',
  'TestResult',
  'Group',
  'target-address',
  'check',
  'check-content-ref',
  'system',
  'interface',
  'connection',
  'relationship',
  'report-request',
  'Benchmark',
  'title',
  'hostname',
]);

type Node = Record<string, unknown>;

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  removeNSPrefix: true,
  processEntities: false,
  htmlEntities: false,
  ignoreDeclaration: true,
  ignorePiTags: true,
  parseTagValue: false,
  parseAttributeValue: false,
  isArray: (name) => REPEATED.has(name),
});

const arr = (v: unknown): unknown[] => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);
const isNode = (v: unknown): v is Node => typeof v === 'object' && v !== null && !Array.isArray(v);
const nodes = (v: unknown): Node[] => arr(v).filter(isNode);
const child = (n: unknown, key: string): unknown => (isNode(n) ? n[key] : undefined);
const kids = (n: unknown, key: string): Node[] => nodes(child(n, key));

/** 要素の文字列（属性つき要素は `#text`）。切って返す。空なら undefined。 */
function text(v: unknown): string | undefined {
  const first = Array.isArray(v) ? v[0] : v;
  const raw = typeof first === 'string' ? first : isNode(first) && typeof first['#text'] === 'string' ? first['#text'] : undefined;
  const s = raw?.trim().slice(0, TEXT_MAX);
  return s ? s : undefined;
}
const attr = (n: unknown, key: string): string | undefined => text(child(n, `@_${key}`));
const texts = (v: unknown): string[] => arr(v).map(text).filter((s): s is string => s !== undefined);

/** 木の中から指定名の要素をすべて集める（見つけた要素の中も探す）。 */
function findAll(root: unknown, name: string, out: Node[] = []): Node[] {
  if (Array.isArray(root)) {
    for (const x of root) findAll(x, name, out);
  } else if (isNode(root)) {
    for (const [k, v] of Object.entries(root)) {
      if (k.startsWith('@_') || k === '#text') continue;
      if (k === name) out.push(...nodes(v));
      findAll(v, name, out);
    }
  }
  return out;
}

// ── 製品・ホスト ─────────────────────────────────────────

const isIso = (s: string | undefined): s is string => s !== undefined && /^\d{4}-\d{2}-\d{2}T/.test(s);
const isIpv4 = (s: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);

/** `cpe:/a:redhat:openscap:1.3.8` → OpenSCAP・1.3.8。読めなければ 'SCAP'。 */
function productFromCpe(cpe: string | undefined): { product: string; version?: string } {
  const m = /^cpe:\/[aoh]:([^:]*):([^:]*)(?::([^:]*))?/.exec(cpe ?? '');
  if (!m) return { product: 'SCAP' };
  const name = m[2].toLowerCase();
  if (name === 'openscap' || name === 'oscap') return { product: 'OpenSCAP', ...(m[3] ? { version: m[3] } : {}) };
  return { product: 'SCAP' };
}

function uniq(list: (string | undefined)[]): string[] {
  return [...new Set(list.filter((s): s is string => !!s))];
}

function makeHost(base: {
  hostnames: string[];
  fqdns: string[];
  ips: string[];
  product: string;
  productVersion?: string;
  observedAt?: string;
}): Omit<ScapHost, 'xccdfFails' | 'ovalTrue' | 'xccdfOvalRefs' | 'counts'> {
  const hostnames = uniq(base.hostnames);
  const fqdns = uniq(base.fqdns);
  const ips = uniq(base.ips);
  return {
    scope: hostnames[0] ?? fqdns[0] ?? ips[0] ?? 'unknown-host',
    hostnames,
    fqdns,
    ips,
    product: base.product,
    ...(base.productVersion ? { productVersion: base.productVersion } : {}),
    ...(base.observedAt ? { observedAt: base.observedAt } : {}),
  };
}

const emptyCounts = (): ScapCounts => ({ pass: 0, fail: 0, error: 0, unknown: 0, other: 0 });

// ── XCCDF ────────────────────────────────────────────────

interface RuleInfo {
  title?: string;
  severity?: string;
  idents: ScapIdent[];
}

/** 文書中の Rule（Group の入れ子の中も含む）を id で引けるようにする。 */
function collectRules(root: unknown): Map<string, RuleInfo> {
  const rules = new Map<string, RuleInfo>();
  for (const r of findAll(root, 'Rule')) {
    const id = attr(r, 'id');
    if (!id || rules.has(id)) continue;
    rules.set(id, {
      title: text(child(r, 'title')),
      severity: attr(r, 'severity'),
      idents: identsOf(r),
    });
  }
  return rules;
}

function identsOf(n: unknown): ScapIdent[] {
  return kids(n, 'ident')
    .map((i) => ({ system: attr(i, 'system') ?? '', value: text(i) ?? '' }))
    .filter((i) => i.value !== '');
}

interface XccdfPartial {
  host: Omit<ScapHost, 'xccdfFails' | 'ovalTrue' | 'xccdfOvalRefs' | 'counts'>;
  xccdfFails: XccdfFail[];
  xccdfOvalRefs: string[];
  counts: ScapCounts;
}

function readTestResult(tr: Node, rules: Map<string, RuleInfo>): XccdfPartial {
  const target = text(child(tr, 'target'));
  const { product, version } = productFromCpe(attr(tr, 'test-system') ?? text(child(tr, 'test-system')));
  const endTime = attr(tr, 'end-time');
  const targetIsHostname = target !== undefined && !isIpv4(target);
  const host = makeHost({
    hostnames: targetIsHostname ? [target] : [],
    fqdns: targetIsHostname && target.includes('.') ? [target] : [],
    ips: [...(target && isIpv4(target) ? [target] : []), ...texts(child(tr, 'target-address'))],
    product,
    productVersion: version,
    observedAt: isIso(endTime) ? endTime : undefined,
  });
  const counts = emptyCounts();
  const fails: XccdfFail[] = [];
  const ovalRefs = new Set<string>();
  for (const rr of kids(tr, 'rule-result')) {
    const idref = attr(rr, 'idref');
    const refs = kids(rr, 'check')
      .flatMap((c) => kids(c, 'check-content-ref'))
      .map((c) => attr(c, 'name'))
      .filter((s): s is string => !!s);
    for (const r of refs) ovalRefs.add(r);
    const result = text(child(rr, 'result'))?.toLowerCase();
    if (result === 'pass') counts.pass += 1;
    else if (result === 'fail') counts.fail += 1;
    else if (result === 'error') counts.error += 1;
    else if (result === 'unknown') counts.unknown += 1;
    else counts.other += 1;
    if (result !== 'fail' || !idref) continue;
    const rule = rules.get(idref);
    const own = attr(rr, 'severity');
    const idents = [...identsOf(rr), ...(rule?.idents ?? [])];
    const seen = new Set<string>();
    fails.push({
      idref,
      severity: own && own.toLowerCase() !== 'unknown' ? own : rule?.severity ?? own,
      title: rule?.title,
      idents: idents.filter((i) => {
        const k = `${i.system}|${i.value}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      }),
      ovalRefs: refs,
    });
  }
  return { host, xccdfFails: fails, xccdfOvalRefs: [...ovalRefs], counts };
}

// ── OVAL ─────────────────────────────────────────────────

interface OvalMeta {
  class?: string;
  title?: string;
  cves: string[];
  severity?: string;
}

function collectOvalMeta(root: unknown): Map<string, OvalMeta> {
  const meta = new Map<string, OvalMeta>();
  for (const od of findAll(root, 'oval_definitions')) {
    for (const d of kids(child(od, 'definitions'), 'definition')) {
      const id = attr(d, 'id');
      if (!id || meta.has(id)) continue;
      const m = child(d, 'metadata');
      meta.set(id, {
        class: attr(d, 'class'),
        title: text(child(m, 'title')),
        cves: kids(m, 'reference')
          .filter((r) => attr(r, 'source')?.toUpperCase() === 'CVE')
          .map((r) => attr(r, 'ref_id'))
          .filter((s): s is string => !!s)
          .slice(0, 50),
        severity: text(child(child(m, 'advisory'), 'severity')),
      });
    }
  }
  return meta;
}

function ovalGenerator(root: unknown): { product: string; version?: string } {
  const gen = findAll(root, 'generator')[0];
  const name = text(child(gen, 'product_name'));
  const version = text(child(gen, 'product_version'));
  if (!name) return { product: 'SCAP' };
  if (name.startsWith('cpe:')) {
    const p = productFromCpe(name);
    return { product: p.product, version: version ?? p.version };
  }
  return { product: name, ...(version ? { version } : {}) };
}

interface OvalPartial {
  host: Omit<ScapHost, 'xccdfFails' | 'ovalTrue' | 'xccdfOvalRefs' | 'counts'>;
  ovalTrue: OvalHit[];
  counts: ScapCounts;
}

function readOvalResults(or: Node, meta: Map<string, OvalMeta>): OvalPartial[] {
  const gen = ovalGenerator(or);
  const systems = kids(child(or, 'results'), 'system');
  return systems.map((sys) => {
    const info = child(child(sys, 'oval_system_characteristics'), 'system_info');
    const hostname = text(child(info, 'primary_host_name'));
    const ips = kids(child(info, 'interfaces'), 'interface').map((i) => text(child(i, 'ip_address')));
    const host = makeHost({
      hostnames: hostname && !isIpv4(hostname) ? [hostname] : [],
      fqdns: hostname && hostname.includes('.') && !isIpv4(hostname) ? [hostname] : [],
      ips: [...ips.filter((s): s is string => !!s)],
      product: gen.product,
      productVersion: gen.version,
    });
    const counts = emptyCounts();
    const hits: OvalHit[] = [];
    for (const d of kids(child(sys, 'definitions'), 'definition')) {
      const id = attr(d, 'definition_id');
      if (!id) continue;
      const result = attr(d, 'result')?.toLowerCase();
      const m = meta.get(id);
      const isVuln = m?.class === 'vulnerability' || m?.class === 'patch';
      if (result === 'error') counts.error += 1;
      else if (result === 'unknown') counts.unknown += 1;
      else if (!isVuln || (result !== 'true' && result !== 'false')) counts.other += 1;
      else if (result === 'true') counts.fail += 1;
      else counts.pass += 1;
      if (result === 'true' && isVuln) {
        hits.push({
          definitionId: id,
          class: m.class as 'vulnerability' | 'patch',
          title: m.title,
          cves: m.cves,
          severity: m.severity,
        });
      }
    }
    return { host, ovalTrue: hits, counts };
  });
}

// ── ARF ──────────────────────────────────────────────────

interface Asset {
  id: string;
  hostnames: string[];
  fqdns: string[];
  ips: string[];
}

function readAssets(root: Node): Asset[] {
  return findAll(child(root, 'asset-report-collection'), 'asset').flatMap((a) => {
    const id = attr(a, 'id');
    const dev = findAll(a, 'computing-device')[0];
    if (!id || !dev) return [];
    const ips = findAll(dev, 'connection').flatMap((c) =>
      kids(c, 'ip-address').flatMap((ip) => [...texts(child(ip, 'ip-v4')), ...texts(child(ip, 'ip-v6'))]),
    );
    return [{ id, hostnames: texts(child(dev, 'hostname')), fqdns: texts(child(dev, 'fqdn')), ips }];
  });
}

function assetIdOfReport(root: Node, reportId: string | undefined, assets: Asset[]): string | undefined {
  if (reportId) {
    for (const rel of findAll(root, 'relationship')) {
      if (!(attr(rel, 'type') ?? '').endsWith('isAbout')) continue;
      if (texts(child(rel, 'subject')).length === 0 && !attr(rel, 'subject')) continue;
      const subjects = [...texts(child(rel, 'subject')), attr(rel, 'subject')];
      if (!subjects.includes(reportId)) continue;
      const refs = [...texts(child(rel, 'ref')), attr(rel, 'ref')].filter((s): s is string => !!s);
      const hit = refs.find((r) => assets.some((a) => a.id === r));
      if (hit) return hit;
    }
  }
  return assets.length === 1 ? assets[0].id : undefined;
}

// ── 組み立て ─────────────────────────────────────────────

function withParts(
  host: Omit<ScapHost, 'xccdfFails' | 'ovalTrue' | 'xccdfOvalRefs' | 'counts'>,
  parts: Partial<Pick<ScapHost, 'xccdfFails' | 'ovalTrue' | 'xccdfOvalRefs' | 'counts'>>,
): ScapHost {
  return { ...host, xccdfFails: [], ovalTrue: [], xccdfOvalRefs: [], counts: emptyCounts(), ...parts };
}

function addCounts(a: ScapCounts, b: ScapCounts): ScapCounts {
  return {
    pass: a.pass + b.pass,
    fail: a.fail + b.fail,
    error: a.error + b.error,
    unknown: a.unknown + b.unknown,
    other: a.other + b.other,
  };
}

/** ARF の資産ごと（資産に結びつかないものは単独で）に、XCCDF と OVAL の部分結果を 1 ホストにまとめる。 */
function mergeHosts(hosts: ScapHost[]): ScapHost {
  const [first, ...rest] = hosts;
  return rest.reduce<ScapHost>(
    (m, h) => ({
      ...m,
      product: m.product === 'SCAP' ? h.product : m.product,
      productVersion: m.productVersion ?? h.productVersion,
      xccdfFails: [...m.xccdfFails, ...h.xccdfFails],
      ovalTrue: [...m.ovalTrue, ...h.ovalTrue],
      xccdfOvalRefs: [...m.xccdfOvalRefs, ...h.xccdfOvalRefs],
      counts: addCounts(m.counts, h.counts),
      observedAt: m.observedAt ?? h.observedAt,
    }),
    first,
  );
}

function parseArf(root: Node): ScapHost[] {
  const assets = readAssets(root);
  const rules = collectRules(root);
  const meta = collectOvalMeta(root);
  const reports = findAll(child(root, 'asset-report-collection'), 'report');
  const groups = new Map<string, ScapHost[]>();
  const loose: ScapHost[] = [];
  for (const rep of reports) {
    const assetId = assetIdOfReport(root, attr(rep, 'id'), assets);
    const asset = assets.find((a) => a.id === assetId);
    const content = child(rep, 'content');
    const partials: ScapHost[] = [
      ...findAll(content, 'TestResult').map((tr) => {
        const p = readTestResult(tr, rules);
        return withParts(p.host, p);
      }),
      ...findAll(content, 'oval_results').flatMap((or) =>
        readOvalResults(or, meta).map((p) => withParts(p.host, p)),
      ),
    ];
    for (const h of partials) {
      if (asset) {
        // 資産の情報でホストを決める（検査側の名前・IP は補足として足す）
        const merged = withParts(
          {
            ...makeHost({
              hostnames: [...asset.hostnames, ...h.hostnames],
              fqdns: [...asset.fqdns, ...h.fqdns],
              ips: [...asset.ips, ...h.ips],
              product: h.product,
              productVersion: h.productVersion,
              observedAt: h.observedAt,
            }),
            scope: asset.hostnames[0] ?? asset.fqdns[0] ?? asset.ips[0] ?? h.scope,
          },
          { xccdfFails: h.xccdfFails, ovalTrue: h.ovalTrue, xccdfOvalRefs: h.xccdfOvalRefs, counts: h.counts },
        );
        groups.set(asset.id, [...(groups.get(asset.id) ?? []), merged]);
      } else {
        loose.push(h);
      }
    }
  }
  return [...[...groups.values()].map(mergeHosts), ...loose];
}

const HostsSchema = z.array(ScapHostSchema);

export function parseScap(xml: string): ParseScapResult {
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) {
    return { ok: false, error: 'DOCTYPE・ENTITY を含む XML は読み込みません（外部実体・実体展開の攻撃を避けるため）。' };
  }
  let doc: Node;
  try {
    const parsed: unknown = parser.parse(xml);
    if (!isNode(parsed)) throw new Error('empty');
    doc = parsed;
  } catch {
    return { ok: false, error: 'XML として読み込めませんでした。' };
  }
  const rootName = Object.keys(doc)[0];

  let format: ScapFormat;
  let hosts: ScapHost[];
  if (rootName === 'Benchmark' || rootName === 'TestResult') {
    format = 'xccdf';
    const rules = collectRules(doc);
    hosts = findAll(doc, 'TestResult').map((tr) => {
      const p = readTestResult(tr, rules);
      return withParts(p.host, p);
    });
  } else if (rootName === 'asset-report-collection') {
    format = 'arf';
    hosts = parseArf(doc);
  } else if (rootName === 'oval_results') {
    format = 'oval';
    const meta = collectOvalMeta(doc);
    hosts = nodes(doc.oval_results).flatMap((or) => readOvalResults(or, meta).map((p) => withParts(p.host, p)));
  } else {
    return { ok: false, error: 'SCAP の結果ファイルとして認識できません（XCCDF の Benchmark/TestResult・ARF・OVAL の結果のいずれでもない）。' };
  }

  const checked = HostsSchema.safeParse(hosts);
  if (!checked.success) return { ok: false, error: 'SCAP の結果の形が想定と異なります。' };
  if (checked.data.length === 0) return { ok: false, error: '検査対象のホスト（TestResult・OVAL の system）が見つかりません。' };
  return { ok: true, format, hosts: checked.data };
}
