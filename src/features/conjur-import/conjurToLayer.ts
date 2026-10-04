import { isAlias, isMap, isScalar, isSeq, parseDocument, type Document, type Node } from 'yaml';
import type { DiagramEdge, DiagramNode, LayerData } from '../../core/model/types';
import { getLocale, translate, type TranslationKey } from '../../i18n';

/**
 * CyberArk（Idira）Conjur / Secrets Manager のポリシー YAML から、NHI と読み取り経路の構成図の下書きを作る。
 *
 * 方針（`kong-import` と同じ）：
 * - **秘密情報を読まない。** ポリシーには値が無い前提だが、取り出すのは id・種類・annotation のキーと
 *   権限（read / execute / update）だけにする。annotation の値は認証方式の判定にだけ使い、図に載せない。
 * - **脅威の知識を持たない。** NHI・人・シークレット管理と読み取り経路に置き換えるだけで、判定は既存のルールに任せる。
 *
 * 対応：
 * - `!host` → 認証方式の annotation（authn-jwt / authn-k8s / authn-iam / authn-azure / authn-gcp）があればワークロードID
 *   （Identity Tier＝Cryptographic）、無ければ API キーで動くサービスアカウント（Identity Tier 未設定＝静的な鍵）
 * - `!variable` → シークレット管理（Conjur）1 つに集約。NHI・人からの線に、取得・更新できる変数の件数を書く
 * - `!user` / `!group` → 変数の権限を持つもの、または host のロールを付与されたものだけ「ユーザー」として描く。
 *   host のロールの付与は「人 → NHI」の線（人による NHI の利用）で表す
 * - `!layer` は描かず、所属する host の説明欄に書く。`!grant` の所属関係をたどって実効権限を求める
 */

const WORKLOAD_AUTHN = ['authn-jwt/', 'authn-k8s/', 'authn-iam/', 'authn-azure/', 'authn-gcp/'];
const RECORD_KINDS = new Set(['host', 'layer', 'variable', 'user', 'group', 'webservice', 'host-factory', 'role', 'resource', 'policy']);
const LIST_LIMIT = 8;

export interface ConjurImportSummary {
  hosts: number;
  layers: number;
  variables: number;
  users: number;
  groups: number;
  permits: number;
  grants: number;
}

export type ConjurImportResult =
  | { ok: true; name: string; layer: LayerData; summary: ConjurImportSummary }
  | { ok: false; error: string };

interface RecordInfo {
  kind: string;
  id: string;
  annotationKeys: string[];
}

interface Ref {
  kind: string;
  id: string;
}

const keyOf = (r: Ref) => `${r.kind}:${r.id}`;
const tagKind = (n: Node) => (n.tag?.startsWith('!') ? n.tag.slice(1) : undefined);
const safeId = (s: string) => s.replace(/[^\w-]/g, '_');

export function conjurToLayer(text: string): ConjurImportResult {
  const locale = getLocale();
  const t = (key: TranslationKey, params?: Record<string, string | number>) => translate(key, locale, params);

  let doc: Document;
  try {
    doc = parseDocument(text);
  } catch (e) {
    return { ok: false, error: t('conjur.error.parse', { message: (e as Error).message }) };
  }
  if (doc.errors.length > 0) {
    return { ok: false, error: t('conjur.error.parse', { message: doc.errors[0].message }) };
  }
  if (!isSeq(doc.contents)) return { ok: false, error: t('conjur.error.notPolicy') };

  const records = new Map<string, RecordInfo>();
  const resolved = new WeakMap<Node, Ref>();
  const permits: { roles: Ref[]; privileges: string[]; resources: Ref[] }[] = [];
  const grants: { roles: Ref[]; members: Ref[] }[] = [];

  const absolute = (id: string, prefix: string) => (id.startsWith('/') ? id.slice(1) : prefix + id);
  const scalarText = (n: unknown) => (isScalar(n) && n.value != null ? String(n.value) : undefined);
  const idOf = (n: Node): string | undefined => (isScalar(n) ? scalarText(n) : isMap(n) ? scalarText(n.get('id', true)) : undefined);
  const stringList = (n: unknown): string[] =>
    isSeq(n) ? n.items.map(scalarText).filter((v): v is string => !!v) : scalarText(n) ? [scalarText(n) as string] : [];

  // 参照（`!host app`・`*alias`・リスト・`!member { role: ... }`）を実体の Ref に解決する。
  const refs = (n: unknown, prefix: string): Ref[] => {
    if (n == null) return [];
    if (isAlias(n)) return refs(n.resolve(doc), prefix);
    if (isSeq(n)) return n.items.flatMap((i) => refs(i, prefix));
    const node = n as Node;
    const known = resolved.get(node);
    if (known) return [known];
    const kind = tagKind(node);
    if (kind === 'member' && isMap(node)) return refs(node.get('role', true), prefix);
    if (!kind) return [];
    const id = idOf(node);
    return id ? [{ kind, id: absolute(id, prefix) }] : [];
  };

  const walk = (n: unknown, prefix: string, seen: Set<Node>) => {
    if (n == null) return;
    if (isAlias(n)) return; // 別名は参照。定義側で登録済み
    if (isSeq(n)) {
      for (const item of n.items) walk(item, prefix, seen);
      return;
    }
    const node = n as Node;
    if (seen.has(node)) return;
    seen.add(node);
    const kind = tagKind(node);
    if (!kind) return;

    if (kind === 'permit' && isMap(node)) {
      permits.push({
        roles: refs(node.get('role', true), prefix),
        privileges: stringList(node.get('privilege', true) ?? node.get('privileges', true)),
        resources: refs(node.get('resource', true) ?? node.get('resources', true), prefix),
      });
      return;
    }
    if (kind === 'grant' && isMap(node)) {
      grants.push({
        roles: refs(node.get('role', true), prefix),
        members: refs(node.get('member', true) ?? node.get('members', true), prefix),
      });
      return;
    }
    if (!RECORD_KINDS.has(kind)) return; // !deny / !revoke / !delete 等は対象外

    const rawId = idOf(node);
    const id = rawId ? absolute(rawId, prefix) : prefix.replace(/\/$/, '');
    const annotations = isMap(node) ? node.get('annotations', true) : undefined;
    const annotationKeys = isMap(annotations) ? annotations.items.map((p) => scalarText(p.key)).filter((k): k is string => !!k) : [];
    const ref = { kind, id };
    resolved.set(node, ref);
    if (!records.has(keyOf(ref))) records.set(keyOf(ref), { kind, id, annotationKeys });
    if (kind === 'policy' && isMap(node)) walk(node.get('body', true), `${id}/`, seen);
  };
  walk(doc.contents, '', new Set());

  const byKind = (k: string) => [...records.values()].filter((r) => r.kind === k);
  if (records.size === 0) return { ok: false, error: t('conjur.error.notPolicy') };

  // メンバーシップ（member → 所属するロール）をたどり、主体ごとの実効ロールを求める。
  const memberOf = new Map<string, Set<string>>();
  for (const g of grants) {
    for (const m of g.members) {
      const set = memberOf.get(keyOf(m)) ?? new Set<string>();
      g.roles.forEach((r) => set.add(keyOf(r)));
      memberOf.set(keyOf(m), set);
    }
  }
  const effectiveRoles = (start: string) => {
    const out = new Set([start]);
    const queue = [start];
    while (queue.length) {
      for (const r of memberOf.get(queue.shift() as string) ?? []) {
        if (!out.has(r)) {
          out.add(r);
          queue.push(r);
        }
      }
    }
    return out;
  };
  const access = (principal: string) => {
    const roles = effectiveRoles(principal);
    const fetch = new Set<string>();
    const update = new Set<string>();
    for (const p of permits) {
      if (!p.roles.some((r) => roles.has(keyOf(r)))) continue;
      for (const res of p.resources.filter((r) => r.kind === 'variable')) {
        if (p.privileges.includes('execute')) fetch.add(res.id);
        if (p.privileges.includes('update')) update.add(res.id);
      }
    }
    return { roles, fetch, update };
  };
  const list = (ids: Iterable<string>) => {
    const all = [...ids].sort();
    const head = all.slice(0, LIST_LIMIT).join(', ');
    return all.length > LIST_LIMIT ? `${head} ${t('conjur.desc.more', { n: all.length - LIST_LIMIT })}` : head || '-';
  };

  const nodes: DiagramNode[] = [];
  const edges: DiagramEdge[] = [];
  const ROW = 150;
  const TOP = 120;
  // NHI（左）→ シークレット管理（中央）← 人（右）。人の線が host の上を横切らないよう、人はシークレット管理の右に置く。
  const COL = { hosts: 60, vault: 400, people: 740 };

  // host（NHI）
  const hosts = byKind('host');
  const hostNode = new Map<string, string>();
  hosts.forEach((h, i) => {
    const workload = h.annotationKeys.some((k) => WORKLOAD_AUTHN.some((p) => k.startsWith(p)));
    const authn = [...new Set(h.annotationKeys.filter((k) => k.startsWith('authn')).map((k) => k.split('/')[0]))];
    const a = access(`host:${h.id}`);
    const layers = [...a.roles].filter((r) => r.startsWith('layer:')).map((r) => r.slice(6));
    const id = `conjur-host-${safeId(h.id)}`;
    hostNode.set(h.id, id);
    nodes.push({
      id,
      type: workload ? 'WORKLOAD_IDENTITY' : 'SERVICE_ACCOUNT',
      x: COL.hosts,
      y: TOP + i * ROW,
      label: h.id,
      description: t('conjur.desc.host', {
        authn: workload ? authn.join(', ') : t('conjur.desc.apiKey'),
        layers: layers.join(', ') || '-',
        vars: list(a.fetch),
      }),
      ...(workload ? { agentAttributes: { identityTier: 'Cryptographic' as const } } : {}),
    });
  });

  // シークレット管理（Conjur）
  const variables = byKind('variable');
  const vaultId = 'conjur-vault';
  const vaultY = TOP + Math.max(0, (Math.max(hosts.length, 1) - 1) * ROW) / 2;
  nodes.push({
    id: vaultId,
    type: 'SECRETS_VAULT',
    x: COL.vault,
    y: vaultY,
    label: t('conjur.node.vault'),
    description: t('conjur.desc.vault', { n: variables.length }),
  });

  const accessEdge = (source: string, fetch: Set<string>, update: Set<string>) => {
    if (fetch.size === 0 && update.size === 0) return;
    const name = [
      fetch.size ? t('conjur.edge.fetch', { n: fetch.size }) : '',
      update.size ? t('conjur.edge.update', { n: update.size }) : '',
    ]
      .filter(Boolean)
      .join(' / ');
    edges.push({
      id: `${source}--${vaultId}`,
      source,
      target: vaultId,
      auth: 'Password',
      network: 'VPC',
      encryption: 'TLS',
      dataFlow: 'bidirectional',
      dataFlowName: name,
    });
  };
  for (const h of hosts) {
    const a = access(`host:${h.id}`);
    accessEdge(hostNode.get(h.id) as string, a.fetch, a.update);
  }

  // 人（変数の権限を持つ、または host のロールを付与されたユーザー・グループ）
  const people = [...byKind('user'), ...byKind('group')];
  let row = 0;
  for (const p of people) {
    const key = `${p.kind}:${p.id}`;
    const a = access(key);
    const actsAs = [...a.roles].filter((r) => r.startsWith('host:')).map((r) => r.slice(5)).filter((h) => hostNode.has(h));
    if (a.fetch.size === 0 && a.update.size === 0 && actsAs.length === 0) continue;
    const id = `conjur-${p.kind}-${safeId(p.id)}`;
    nodes.push({
      id,
      type: 'USER',
      x: COL.people,
      y: TOP + row++ * ROW,
      label: t(p.kind === 'user' ? 'conjur.node.user' : 'conjur.node.group', { id: p.id }),
      description: t('conjur.desc.person', { vars: list(a.fetch) }),
    });
    accessEdge(id, a.fetch, a.update);
    for (const h of actsAs) {
      const target = hostNode.get(h) as string;
      edges.push({
        id: `${id}--${target}`,
        source: id,
        target,
        auth: 'Password',
        network: 'VPC',
        encryption: 'TLS',
        dataFlowName: t('conjur.edge.actAs'),
      });
    }
  }

  // 組織内（マクロセグメンテーション：Security Zone）で全体を囲む。
  const PAD = 40;
  const xs = nodes.map((n) => n.x);
  const ys = nodes.map((n) => n.y);
  const left = Math.min(...xs) - PAD;
  const top = Math.min(...ys) - PAD - 30;
  const boundary = {
    id: 'conjur-b-internal',
    type: 'ROUNDED' as const,
    x: left,
    y: top,
    width: Math.max(...xs) + 128 + PAD - left,
    height: Math.max(...ys) + 96 + PAD - top,
    trustLevel: 'Internal' as const,
    macroTrust: 'Security Zone' as const,
  };

  return {
    ok: true,
    name: t('conjur.templateName'),
    layer: { nodes, edges, boundaries: [boundary], annotations: [] },
    summary: {
      hosts: hosts.length,
      layers: byKind('layer').length,
      variables: variables.length,
      users: byKind('user').length,
      groups: byKind('group').length,
      permits: permits.length,
      grants: grants.length,
    },
  };
}
