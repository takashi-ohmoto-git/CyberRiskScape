import type { Finding, LayerKey } from '../../core/model/types';
import type { BloodhoundQuery } from './bloodhoundQueries';
import type { CypherNode } from './parseCypherResponse';

/**
 * BloodHound CE の問い合わせの結果を共通モデルの指摘にする（1 つの問い合わせ＝指摘 1 件。該当 0 件なら指摘にしない）。
 * - 指摘は図の DIRECTORY（AD CS の問い合わせは CERTIFICATE_AUTHORITY。無ければ DIRECTORY）に載せる
 * - **ユーザーの名前は残さない**（件数だけ）。名前を残すのは資産・構成の種類だけ（2026-11-15 ユーザー決定）
 * - SID 等の内部識別子は持たない
 * DOM にも Node にも依存しない純粋関数。
 */

export const BLOODHOUND_PRODUCT = 'BloodHound CE';

/** 名前を残してよい種類（資産・構成）。これ以外（User・不明な種類）は件数だけ。 */
const NAMED_KINDS: ReadonlySet<string> = new Set([
  'Computer',
  'Group',
  'GPO',
  'OU',
  'Container',
  'Domain',
  'CertTemplate',
  'EnterpriseCA',
  'RootCA',
  'AIACA',
  'NTAuthStore',
  'IssuancePolicy',
]);

/** 指摘 1 件に残す名前の上限。 */
const MAX_NAMES = 20;
const TEXT_MAX = 200;

type Subject = { layer: LayerKey; nodeId: string };

export interface BloodhoundQueryReport {
  queryId: string;
  title: string;
  /** 問い合わせの結果が渡されたか（API で失敗した・ファイルが無い問い合わせは false）。 */
  evaluated: boolean;
  /** 数えた主体の数（Tier Zero を除いた後）。 */
  count: number;
  /** Tier Zero のため数えなかった数。 */
  excludedTierZero: number;
  /** 種類ごとの件数。 */
  byKind: Record<string, number>;
}

export interface BloodhoundToFindingsInput {
  queries: readonly BloodhoundQuery[];
  /** 問い合わせ ID → 応答のノード。無い問い合わせは評価しない。 */
  results: ReadonlyMap<string, readonly CypherNode[]>;
  subjects: { directory?: Subject; ca?: Subject };
  scope: string;
  importedAt: string;
}

const KIND_LABEL: Record<string, string> = {
  User: 'ユーザー',
  Computer: 'コンピューター',
  Group: 'グループ',
  GPO: 'GPO',
  OU: 'OU',
  Domain: 'ドメイン',
  CertTemplate: '証明書テンプレート',
  EnterpriseCA: 'CA',
};

function summary(byKind: Record<string, number>, names: readonly string[]): string {
  const parts = Object.entries(byKind)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, n]) => `${KIND_LABEL[k] ?? k} ${n}`);
  const head = parts.join('・');
  const text = names.length ? `${head}（${names.join(', ')}）` : head;
  return text.length > TEXT_MAX ? `${text.slice(0, TEXT_MAX - 1)}…` : text;
}

export function bloodhoundToFindings(input: BloodhoundToFindingsInput): {
  findings: Finding[];
  reports: BloodhoundQueryReport[];
} {
  const findings: Finding[] = [];
  const reports: BloodhoundQueryReport[] = [];
  for (const q of input.queries) {
    const nodes = input.results.get(q.id);
    if (!nodes) {
      reports.push({ queryId: q.id, title: q.title, evaluated: false, count: 0, excludedTierZero: 0, byKind: {} });
      continue;
    }
    const counted = q.excludeTierZero ? nodes.filter((n) => !n.isTierZero) : [...nodes];
    const byKind: Record<string, number> = {};
    for (const n of counted) {
      const k = n.kind ?? 'Unknown';
      byKind[k] = (byKind[k] ?? 0) + 1;
    }
    reports.push({
      queryId: q.id,
      title: q.title,
      evaluated: true,
      count: counted.length,
      excludedTierZero: nodes.length - counted.length,
      byKind,
    });
    if (counted.length === 0) continue;

    const names = [
      ...new Set(counted.filter((n) => n.kind !== undefined && NAMED_KINDS.has(n.kind) && n.name).map((n) => n.name!)),
    ]
      .sort()
      .slice(0, MAX_NAMES);
    const subject = q.subject === 'ca' ? (input.subjects.ca ?? input.subjects.directory) : input.subjects.directory;
    findings.push({
      id: `${BLOODHOUND_PRODUCT}:${input.scope}:${q.id}`,
      source: { format: 'bloodhound', product: BLOODHOUND_PRODUCT, scope: input.scope, importedAt: input.importedAt },
      externalId: q.id,
      identifiers: [{ scheme: 'bloodhound-query', value: q.id }],
      title: `${q.title}：${counted.length} 件`.slice(0, TEXT_MAX),
      severity: q.severity,
      canonicalIds: [...q.canonicalIds],
      ...(subject ? { subject } : {}),
      resource: { label: summary(byKind, names), type: 'Active Directory' },
      observedAt: input.importedAt,
    });
  }
  return { findings, reports };
}
