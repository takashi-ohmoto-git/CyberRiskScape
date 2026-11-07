import { translate, type TranslationKey } from '../../i18n';
import type { AuthType, NetworkType } from '../../core/model/types';
import type { ContractorBasis, ContractorPathRow, ContractorPaths, RestrictionState } from './buildContractorPaths';

/** 委託先の接続経路（ContractorPaths）を Markdown / CSV / JSON に整形する。 */

type T = (key: TranslationKey, params?: Record<string, string | number>) => string;

const AUTH_KEY: Record<AuthType, TranslationKey> = {
  None: 'panels.edge.auth.none',
  Password: 'panels.edge.auth.password',
  ApiKey: 'panels.edge.auth.apiKey',
  Token: 'panels.edge.auth.token',
  Passkey: 'panels.edge.auth.passkey',
  Certificate: 'panels.edge.auth.certificate',
  MFA: 'panels.edge.auth.mfa',
};

const NETWORK_KEY: Record<NetworkType, TranslationKey> = {
  Internet: 'panels.edge.network.internet',
  VPN: 'panels.edge.network.vpn',
  VPC: 'panels.edge.network.vpc',
};

const oneLine = (s: string) => s.replace(/\s+/g, ' ').trim();
const maker = (paths: ContractorPaths): T => (key, params) => translate(key, paths.locale, params);

const stateText = (t: T, s: RestrictionState) => t(`contractor.state.${s}` as TranslationKey);
const basisText = (t: T, b: ContractorBasis) => t(`contractor.basis.${b}` as TranslationKey);

function reasonText(t: T, r: ContractorPathRow): string {
  const parts: string[] = [];
  for (const code of r.reasons) {
    if (code === 'notMfa') parts.push(t('contractor.reason.notMfa'));
    if (code === 'sensitiveReach') parts.push(t('contractor.reason.sensitiveReach', { count: r.reachableData.length }));
    if (code === 'weakRestrictions') parts.push(t('contractor.reason.weakRestrictions', { count: r.weakCount }));
  }
  return parts.length > 0 ? parts.join(' / ') : t('contractor.reason.none');
}

/** 重大度の高い順に名前の重複を除いて上位 THREAT_LIMIT 件。残りは件数で示す（全件は JSON）。 */
const THREAT_LIMIT = 3;
function threatText(t: T, r: ContractorPathRow, none: string): string {
  const seen = new Set<string>();
  const uniq = r.threats.filter((x) => !seen.has(x.name) && seen.add(x.name));
  if (uniq.length === 0) return none;
  const shown = uniq.slice(0, THREAT_LIMIT).map((x) => `${x.name} (${x.severity})`);
  const rest = uniq.length - shown.length;
  return rest > 0 ? `${shown.join(', ')}${t('contractor.threats.more', { count: rest })}` : shown.join(', ');
}

const nodeRef = (id: string | null, label: string | null, none: string) => (id ? (label ?? id) : none);

/** 1 行を列の値（見出しキー付き）に展開する。Markdown と CSV で共有。 */
function cells(t: T, r: ContractorPathRow): [TranslationKey, string][] {
  const none = t('contractor.none');
  return [
    ['contractor.col.rank', String(r.rank)],
    ['contractor.col.basis', r.bases.map((b) => basisText(t, b)).join(' / ')],
    ['contractor.col.from', nodeRef(r.fromId, r.fromLabel, none)],
    ['contractor.col.via', nodeRef(r.viaId, r.viaLabel, none)],
    ['contractor.col.to', nodeRef(r.toId, r.toLabel, none)],
    ['contractor.col.network', t(NETWORK_KEY[r.network])],
    ['contractor.col.auth', `${t(AUTH_KEY[r.auth])} (ZTMM ${r.ztmm})`],
    ['contractor.col.mfa', t(r.mfaEquivalent ? 'contractor.mfa.yes' : 'contractor.mfa.no')],
    ['contractor.col.sourceIp', stateText(t, r.sourceIpRestriction)],
    ['contractor.col.remote', stateText(t, r.remoteAccessRestriction)],
    ['contractor.col.log', stateText(t, r.accessLog)],
    ['contractor.col.logSink', r.logSink ?? none],
    ['contractor.col.data', r.reachableData.length > 0 ? r.reachableData.map((d) => d.label).join(', ') : none],
    [
      'contractor.col.threats',
      threatText(t, r, none),
    ],
    ['contractor.col.reason', reasonText(t, r)],
  ];
}

const mdCell = (s: string) => oneLine(s).replace(/\|/g, '\\|');

export function contractorPathsToMarkdown(paths: ContractorPaths): string {
  const t = maker(paths);
  const out: string[] = [];
  out.push(`# ${t('contractor.title', { system: paths.system, layer: paths.layer })}`, '');
  out.push(`> ${t('contractor.disclaimer')}`, '');
  out.push(`- ${t('contractor.system', { system: paths.system })}`);
  out.push(`- ${t('contractor.generated', { date: paths.generatedAt, product: paths.product })}`);
  out.push(`- ${t('contractor.howTo')}`, '');
  if (paths.rows.length === 0) {
    out.push(t('contractor.noRows'));
    return `${out.join('\n')}\n`;
  }
  const head = cells(t, paths.rows[0]).map(([k]) => t(k));
  out.push(`| ${head.join(' | ')} |`, `| ${head.map(() => '---').join(' | ')} |`);
  for (const r of paths.rows) out.push(`| ${cells(t, r).map(([, v]) => mdCell(v)).join(' | ')} |`);
  return `${out.join('\n')}\n`;
}

const csvCell = (s: string) => (/[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);

/** CSV は 1 行目に注記（判別は推定・候補であること）、2 行目から表を出す。 */
export function contractorPathsToCsv(paths: ContractorPaths): string {
  const t = maker(paths);
  const lines = [csvCell(t('contractor.disclaimer'))];
  if (paths.rows.length === 0) return `${[...lines, csvCell(t('contractor.noRows'))].join('\n')}\n`;
  lines.push(cells(t, paths.rows[0]).map(([k]) => csvCell(t(k))).join(','));
  for (const r of paths.rows) lines.push(cells(t, r).map(([, v]) => csvCell(oneLine(v))).join(','));
  return `${lines.join('\n')}\n`;
}

/** JSON は ContractorPaths をそのまま出す（キーは英語）。注記は disclaimer に入れる。 */
export function contractorPathsToJson(paths: ContractorPaths): string {
  const t = maker(paths);
  return JSON.stringify({ disclaimer: t('contractor.disclaimer'), ...paths }, null, 2);
}
