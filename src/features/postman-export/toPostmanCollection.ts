import type { DiagramEdge, DiagramNode, LayerKey, ProjectMeta, ThreatView } from '../../core/model/types';
import { formatElementalId } from '../../core/model/elementalId';
import { BRANDING } from '../../core/branding';
import { getLocale, translate, type TranslationKey } from '../../i18n';
import { getTestTemplates, type TestTemplate } from './testTemplates';

/**
 * 検出した脅威から、検証用リクエストの Postman Collection（v2.1 JSON）を作る。
 *
 * - どの脅威にどのテストを作るかは `data/test-templates/postman.yaml`（canonicalId で対応）。
 *   コードはテストの中身を持たない。
 * - 宛先は、脅威の対象がノードならそのノード、エッジならエッジの受け側のノード。
 *   同じノードに同じテンプレートが複数の脅威から当たる場合は 1 件にまとめる。
 * - ホスト名・トークン・ID は図に無いので Postman の変数にする（利用者が環境で埋める）。
 *   `$NODE` は対象ノードの ElementalID（例: C7）に置き換える。
 */

export const POSTMAN_SCHEMA_URL = 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json';

export interface PostmanExportInput {
  threats: ThreatView[];
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  projectMeta: ProjectMeta;
  layer: LayerKey;
}

export interface PostmanExportSummary {
  /** 生成したリクエスト数。 */
  requests: number;
  /** テストを作った脅威の数。 */
  coveredThreats: number;
  /** HTTP で確かめる対応表が無く、テストを作らなかった脅威の数。 */
  uncoveredThreats: number;
}

interface PostmanVariable {
  key: string;
  value: string;
  description?: string;
}

/** 対象ノードに依らず使う変数。生成したリクエストから参照されたものだけを載せる。 */
const SHARED_VARIABLES: { key: string; value: string; descriptionKey: TranslationKey }[] = [
  { key: 'token_user_a', value: '', descriptionKey: 'postman.var.tokenUserA' },
  { key: 'object_id_user_b', value: '', descriptionKey: 'postman.var.objectIdUserB' },
  { key: 'canary', value: 'CRS-CANARY-7F3A9C', descriptionKey: 'postman.var.canary' },
  { key: 'system_prompt_marker', value: 'CRS-SYSPROMPT-MARKER', descriptionKey: 'postman.var.systemPromptMarker' },
];

export function toPostmanCollection(input: PostmanExportInput): {
  collection: Record<string, unknown>;
  summary: PostmanExportSummary;
} {
  const locale = getLocale();
  const t = (key: TranslationKey, params?: Record<string, string | number>) => translate(key, locale, params);
  const templates = getTestTemplates(locale);

  const byCanonical = new Map<string, TestTemplate>();
  for (const tpl of templates) for (const c of tpl.match.canonicalIds) byCanonical.set(c, tpl);

  const nodeById = new Map(input.nodes.map((n) => [n.id, n]));
  const edgeById = new Map(input.edges.map((e) => [e.id, e]));
  const elementalId = (n: DiagramNode) => (n.seq != null ? formatElementalId('node', n.seq) : n.id);
  const nodeName = (n: DiagramNode) => n.label?.trim() || n.type;

  // (テンプレート, 宛先ノード) ごとに脅威を束ねる。
  const groups = new Map<string, { tpl: TestTemplate; node: DiagramNode; threats: ThreatView[] }>();
  const covered = new Set<string>();
  for (const threat of input.threats) {
    const tpl = threat.canonicalId ? byCanonical.get(threat.canonicalId) : undefined;
    if (!tpl || !threat.subject) continue;
    const nodeId =
      threat.subject.kind === 'node'
        ? threat.subject.id
        : threat.subject.kind === 'edge'
          ? edgeById.get(threat.subject.id)?.target
          : undefined;
    const node = nodeId ? nodeById.get(nodeId) : undefined;
    if (!node) continue;
    const key = `${tpl.id}|${node.id}`;
    const group = groups.get(key) ?? { tpl, node, threats: [] };
    group.threats.push(threat);
    groups.set(key, group);
    covered.add(threat.id);
  }

  const variables = new Map<string, PostmanVariable>();
  const folders = new Map<string, { node: DiagramNode; items: Record<string, unknown>[] }>();

  for (const { tpl, node, threats } of groups.values()) {
    const eid = elementalId(node);
    const sub = (s: string) => s.split('$NODE').join(eid);

    variables.set(`${eid}_host`, { key: `${eid}_host`, value: '', description: t('postman.var.host', { node: `${eid} ${nodeName(node)}` }) });
    variables.set(`${eid}_path`, { key: `${eid}_path`, value: '/', description: t('postman.var.path', { node: `${eid} ${nodeName(node)}` }) });
    for (const v of tpl.variables ?? []) {
      variables.set(sub(v.key), { key: sub(v.key), value: sub(v.value), description: v.description });
    }

    const threatLines = threats
      .map((th) => `- [${th.severity}] ${th.name ?? th.category}（${th.ruleId ?? th.id}）`)
      .join('\n');
    const description = [
      sub(tpl.purpose),
      '',
      `**${t('postman.desc.threats')}**`,
      threatLines,
      '',
      `> ${t('postman.desc.authorizedOnly')}`,
    ].join('\n');

    const request: Record<string, unknown> = {
      method: tpl.request.method,
      header: (tpl.request.headers ?? []).map((h) => ({ key: h.key, value: sub(h.value) })),
      url: sub(tpl.request.url),
      description,
    };
    if (tpl.request.body !== undefined) {
      request.body = { mode: 'raw', raw: sub(tpl.request.body), options: { raw: { language: 'json' } } };
    }

    const folder = folders.get(node.id) ?? { node, items: [] };
    folder.items.push({
      name: tpl.name,
      request,
      event: [{ listen: 'test', script: { type: 'text/javascript', exec: tpl.tests.trimEnd().split('\n') } }],
    });
    folders.set(node.id, folder);
  }

  // 生成したリクエストが参照する共通変数だけを足す（`{{key}}` とテストスクリプトの `pm.variables.get("key")`）。
  const generated = JSON.stringify([...folders.values()].map((f) => f.items));
  for (const v of SHARED_VARIABLES) {
    if (generated.includes(v.key)) {
      variables.set(v.key, { key: v.key, value: v.value, description: t(v.descriptionKey) });
    }
  }

  const ordered = [...folders.values()].sort((a, b) => (a.node.seq ?? 0) - (b.node.seq ?? 0));
  const target = input.projectMeta.systemName.trim() || input.projectMeta.name.trim() || BRANDING.name;
  const uncovered = input.threats.filter((th) => !covered.has(th.id)).length;

  const collection = {
    info: {
      name: t('postman.collectionName', { target, layer: input.layer }),
      description: [
        t('postman.desc.intro', { product: BRANDING.name, layer: input.layer }),
        '',
        t('postman.desc.howTo'),
        '',
        `> ${t('postman.desc.authorizedOnly')}`,
        '',
        t('postman.desc.summary', { requests: groups.size, covered: covered.size, uncovered }),
      ].join('\n'),
      schema: POSTMAN_SCHEMA_URL,
    },
    variable: [...variables.values()].sort((a, b) => a.key.localeCompare(b.key)),
    item: ordered.map((f) => ({ name: `${elementalId(f.node)} ${nodeName(f.node)}`, item: f.items })),
  };

  return {
    collection,
    summary: { requests: groups.size, coveredThreats: covered.size, uncoveredThreats: uncovered },
  };
}
