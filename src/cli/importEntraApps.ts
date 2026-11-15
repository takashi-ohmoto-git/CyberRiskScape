import { resolveProject } from './analyze';
import { LAYER_KEYS, MAX_FINDINGS } from '../core/model/types';
import { formatElementalId } from '../core/model/elementalId';
import { deserializeProject } from '../features/persistence/serialize';
import type { PersistedProject } from '../features/persistence/schema';
import { replaceFindings, type FindingsDiff } from '../features/findings-import/replaceFindings';
import { lookupNode, type ImportNodeRef } from '../features/findings-import/resolveNode';
import { BUNDLED_GRAPH_PERMISSIONS, type GraphPermissionMap } from '../features/entra-apps-import/graphPermissions';
import {
  parseAssignments,
  parseGrants,
  parseServicePrincipals,
  type GraphServicePrincipal,
} from '../features/entra-apps-import/parseGraph';
import {
  ENTRA_APPS_PRODUCT,
  entraAppsToFindings,
  type EntraAppsCheck,
  type ExternalApp,
} from '../features/entra-apps-import/entraAppsToFindings';

/**
 * CLI `import-entra-apps`：Microsoft Graph の外部アプリ・同意の在庫を指摘として図の IdP に保存し、外部アプリと図の
 * アプリ系のノードを突き合わせた報告を出す（plan §2.144）。図は変えない（指摘を足すだけ）。
 * ファイル・API の I/O は呼び出し側（main.ts）。
 */

export const DEFAULT_ENTRA_APPS_SCOPE = 'default';

/** 突き合わせに使う図のアプリ系の型。 */
const APP_TYPES: ReadonlySet<string> = new Set(['SAAS', 'OAUTH_CLIENT', 'OTHER_APP', 'THIRD_PARTY_EXTENSION', 'CRM', 'MAIL', 'CHAT']);

export interface EntraAppsRaw {
  servicePrincipals: unknown;
  /** Microsoft Graph のサービスプリンシパル（appRoles を含む）。 */
  graphServicePrincipal?: unknown;
  graphAppRoleAssignedTo?: unknown;
  oauth2PermissionGrants?: unknown;
}

export interface ImportEntraAppsOptions {
  tenantId: string;
  idpNode?: string;
  scope?: string;
  perms?: GraphPermissionMap;
  importedAt?: string;
}

export interface ImportEntraAppsOutput {
  project: PersistedProject;
  scope: string;
  idp: { kind: 'found'; node: string } | { kind: 'none' | 'many' | 'unknownNode' | 'ambiguous' | 'wrongType' };
  checks: EntraAppsCheck[];
  externalCount: number;
  externalApps: ExternalApp[];
  /** Graph のアプリ単独の権限を判定できなかった（Microsoft Graph のサービスプリンシパル・appRoles が無い）。 */
  graphRolesMissing: boolean;
  invalid: number;
  stored: number;
  diff: FindingsDiff;
}

const nodeName = (n: ImportNodeRef) => `${n.seq != null ? formatElementalId('node', n.seq) : n.id} ${n.label?.trim() || n.type}`;

export function importEntraApps(rawProject: unknown, raw: EntraAppsRaw, options: ImportEntraAppsOptions): ImportEntraAppsOutput {
  const resolved = resolveProject(rawProject);
  const loaded = deserializeProject(rawProject);
  if (!loaded) throw new Error('プロジェクト JSON の形式が不正です。');
  const nodes: ImportNodeRef[] = LAYER_KEYS.flatMap((layer) =>
    resolved.layers[layer].nodes.map((n) => ({ id: n.id, layer, seq: n.seq, type: n.type, label: n.label })),
  );

  let idpNode: ImportNodeRef | undefined;
  let idp: ImportEntraAppsOutput['idp'];
  if (options.idpNode !== undefined) {
    const r = lookupNode(nodes, options.idpNode);
    if (r.kind !== 'found') idp = { kind: r.kind === 'ambiguous' ? 'ambiguous' : 'unknownNode' };
    else if (r.node.type !== 'IDENTITY_PROVIDER') idp = { kind: 'wrongType' };
    else idpNode = r.node;
  } else {
    const hits = nodes.filter((n) => n.type === 'IDENTITY_PROVIDER');
    if (hits.length === 1) idpNode = hits[0];
    else idp = { kind: hits.length === 0 ? 'none' : 'many' };
  }
  if (idpNode) idp = { kind: 'found', node: nodeName(idpNode) };

  let invalid = 0;
  const need = <T>(r: { ok: true; items: T[]; invalid: number } | { ok: false; error: string }): T[] => {
    if (!r.ok) throw new Error(r.error);
    invalid += r.invalid;
    return r.items;
  };
  const sps = need(parseServicePrincipals(raw.servicePrincipals));
  // Microsoft Graph のサービスプリンシパル（appRoles つき）で一覧の同じ ID を置き換える
  const graphSp: GraphServicePrincipal[] = raw.graphServicePrincipal === undefined ? [] : need(parseServicePrincipals(raw.graphServicePrincipal));
  const merged = [...sps.filter((s) => !graphSp.some((g) => g.id === s.id)), ...graphSp];
  const perms = options.perms ?? BUNDLED_GRAPH_PERMISSIONS;
  const graphRolesMissing = !merged.some((s) => s.appId === perms.graphAppId && s.appRoles.length > 0);

  const scope = (options.scope ?? DEFAULT_ENTRA_APPS_SCOPE).slice(0, 200);
  const conv = entraAppsToFindings({
    servicePrincipals: merged,
    grants: raw.oauth2PermissionGrants === undefined ? [] : need(parseGrants(raw.oauth2PermissionGrants)),
    graphAssignments: raw.graphAppRoleAssignedTo === undefined ? [] : need(parseAssignments(raw.graphAppRoleAssignedTo)),
    tenantId: options.tenantId,
    perms,
    ...(idpNode ? { subject: { layer: idpNode.layer, nodeId: idpNode.id } } : {}),
    diagramApps: nodes.filter((n) => APP_TYPES.has(n.type) && n.label?.trim()).map((n) => ({ label: nodeName(n), name: n.label!.trim() })),
    scope,
    importedAt: options.importedAt ?? new Date().toISOString(),
  });
  const r = replaceFindings(loaded.findings, conv.findings, ENTRA_APPS_PRODUCT, scope);
  if (r.findings.length > MAX_FINDINGS) throw new Error(`指摘が上限（${MAX_FINDINGS} 件）を超えます: ${r.findings.length} 件`);
  const project: PersistedProject = { ...loaded };
  if (r.findings.length > 0) project.findings = r.findings;
  else delete project.findings;
  return {
    project,
    scope,
    idp: idp!,
    checks: conv.checks,
    externalCount: conv.externalCount,
    externalApps: conv.externalApps,
    graphRolesMissing,
    invalid,
    stored: conv.findings.length,
    diff: r.diff,
  };
}

const IDP_TEXT: Record<Exclude<ImportEntraAppsOutput['idp']['kind'], 'found'>, string> = {
  none: '未結合（図に IdP が無い）',
  many: '未結合（図に IdP が複数ある。--idp-node で指定してください）',
  unknownNode: '未結合（指定されたノードが図に無い）',
  ambiguous: '未結合（C 番号が複数のレイヤーに該当。ノード ID で指定してください）',
  wrongType: '未結合（指定されたノードが IdP ではない）',
};

const cell = (s: string) => s.replace(/[\r\n]+/g, ' ').replace(/\|/g, '\\|');

export function entraAppsReportToMarkdown(out: ImportEntraAppsOutput): string {
  const notable = out.externalApps.filter((a) => a.appPermissions.length > 0 || a.tenantWideScopes.length > 0 || a.userConsentCount > 0);
  const lines = [
    '# Microsoft Graph（外部アプリ・同意）の取り込みレポート',
    '',
    '- 外部アプリ＝所有テナントが自組織でも Microsoft のサービスでもないアプリ。強い権限は data/finding-maps/graph-permissions.yaml の一覧で判定した。',
    '- 資格情報は有効期限だけを読み、値・ヒントは保存しない。利用者ごとの同意は件数だけで、利用者は特定しない。図は変えていない。',
    `- scope: ${out.scope}`,
    `- IdP: ${out.idp.kind === 'found' ? out.idp.node : IDP_TEXT[out.idp.kind]}`,
    ...(out.graphRolesMissing ? ['- **Microsoft Graph のサービスプリンシパル（appRoles）が無いため、アプリ単独の権限は判定していない。**'] : []),
    '',
    `## 件数（保存 ${out.stored} 件。新規 ${out.diff.added} / 解消 ${out.diff.resolved} / 継続 ${out.diff.continued}）`,
    '',
    `- 外部アプリ ${out.externalCount} 件`,
    ...out.checks.map((c) => `- ${c.title}：${c.count} 件`),
    '',
    `## 強い権限・同意のある外部アプリ（${notable.length} 件）`,
    '',
  ];
  if (notable.length === 0) lines.push('- 該当なし', '');
  else {
    lines.push('| アプリ | 発行元 | アプリ単独の権限 | テナント全体の同意 | 利用者ごとの同意 | 図 |', '| --- | --- | --- | --- | --- | --- |');
    for (const a of notable) {
      lines.push(
        `| ${[a.name, a.verifiedPublisher ?? '未確認', a.appPermissions.join(' ') || '—', a.tenantWideScopes.join(' ') || '—', a.userConsentCount ? `${a.userConsentCount} 件` : '—', a.diagramNode ?? '**図に無い**'].map(cell).join(' | ')} |`,
      );
    }
    lines.push('', '> 「図に無い」は、図のアプリ系のノード（SaaS・OAuth クライアント等）のラベルと表示名が一致しなかったもの。描き漏れの候補で、判定ではない。', '');
  }
  if (out.invalid > 0) lines.push(`- 形が合わず読めなかった要素 ${out.invalid} 件`, '');
  return lines.join('\n');
}

export function entraAppsReportToJson(out: ImportEntraAppsOutput): Record<string, unknown> {
  return {
    schemaVersion: 1,
    kind: 'cyberriskscape-entra-apps-import',
    scope: out.scope,
    idp: out.idp,
    stored: out.stored,
    diff: out.diff,
    externalCount: out.externalCount,
    checks: out.checks,
    graphRolesMissing: out.graphRolesMissing,
    externalApps: out.externalApps,
    invalid: out.invalid,
  };
}
