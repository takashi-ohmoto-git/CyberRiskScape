import type { Finding, FindingCondition, FindingConditionKind, FindingIdentifier, LayerKey, Severity } from '../../core/model/types';
import { MAX_FINDING_CONDITIONS, MAX_FINDING_OPEN_QUESTIONS } from '../../core/model/types';
import { capFindings } from '../findings-import/replaceFindings';
import { attackClassToCanonicalIds, type SecurityAuditMapping } from '../findings-report/findingMap';
import { scrubUri } from '../sarif-import/sarifToFindings';
import type { AuditItem, LedgerUnit } from './parseSecurityAudit';

/**
 * security-audit の指摘を共通モデルの指摘（`Finding`）へ変換する純粋関数（docs/architecture.md §8.9）。
 * execution（payloads）・remediation・evidence・root_cause の本文・trace の中間と説明は持たない。
 * rejected は保存せず件数だけ数える。
 */

export const SECURITY_AUDIT_PRODUCT = 'Cloudflare security-audit';

const TEXT_MAX = 200;
const ATTACK_CLASS_SCHEME = 'security-audit-attack-class';

const SEVERITY: Record<string, Severity> = {
  informational: 'Low',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
};

const CONDITION_KIND: Record<string, FindingConditionKind> = {
  network_routing: 'reachability',
  authentication_level: 'authentication',
  authorization_role: 'authorization',
  system_configuration: 'configuration',
  user_interaction: 'user-interaction',
};

/** 改行・制御文字を空白に落として切る（表やログに崩れて出ないように）。 */
function clean(s: string, max = TEXT_MAX): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, max);
}

export interface SecurityAuditReport {
  confirmed: number;
  unverified: number;
  /** 保存しなかった（反証された）指摘の数。 */
  rejected: number;
  /** 保存した指摘のうち、canonicalId に対応づけできなかった数。 */
  unmapped: number;
  /** 同じ指紋が重複していたため捨てた数。 */
  duplicates: number;
  /** 上限（MAX_FINDINGS）で保存しなかった数。 */
  overLimit: number;
}

export interface SecurityAuditConversion {
  findings: Finding[];
  report: SecurityAuditReport;
}

export interface SecurityAuditToFindingsInput {
  items: readonly AuditItem[];
  ledger?: readonly LedgerUnit[];
  map: readonly SecurityAuditMapping[];
  scope: string;
  subject?: { layer: LayerKey; nodeId: string };
  importedAt: string;
}

function labelOf(trace: readonly { kind?: string; file: string; line?: number }[]): string | undefined {
  const t = trace.find((x) => x.kind === 'entrypoint') ?? trace[0];
  if (!t) return undefined;
  const file = scrubUri(t.file);
  if (!file) return undefined;
  return clean(`${file}${t.line !== undefined ? `:${t.line}` : ''}`);
}

export function securityAuditToFindings(input: SecurityAuditToFindingsInput): SecurityAuditConversion {
  const classesOf = new Map<string, Set<string>>();
  for (const u of input.ledger ?? []) {
    if (!u.attackClass) continue;
    for (const fp of u.fingerprints) {
      const set = classesOf.get(fp) ?? new Set<string>();
      set.add(u.attackClass);
      classesOf.set(fp, set);
    }
  }

  const source = {
    format: 'security-audit' as const,
    product: SECURITY_AUDIT_PRODUCT,
    scope: input.scope.slice(0, 200),
    importedAt: input.importedAt.slice(0, 40),
  };
  const all: Finding[] = [];
  const seen = new Set<string>();
  let rejected = 0;
  let duplicates = 0;
  for (const it of input.items) {
    if (it.verdict === 'rejected') {
      rejected += 1;
      continue;
    }
    if (seen.has(it.fingerprint)) {
      duplicates += 1;
      continue;
    }
    seen.add(it.fingerprint);

    const classes = [...(classesOf.get(it.fingerprint) ?? [])];
    const canonicalIds = new Set<string>();
    for (const c of classes) for (const id of attackClassToCanonicalIds(input.map, c) ?? []) canonicalIds.add(id);
    const identifiers: FindingIdentifier[] = [
      { scheme: 'security-audit-fingerprint', value: it.fingerprint },
      ...classes.filter((c) => c.length <= TEXT_MAX).map((value) => ({ scheme: ATTACK_CLASS_SCHEME, value })),
    ].slice(0, 20);
    const label = labelOf(it.trace);

    const base = {
      // fingerprint はリポジトリ内でだけ一意なので、SCAP と同じく scope を前に付けて別リポジトリとの衝突を避ける
      id: `${SECURITY_AUDIT_PRODUCT}:${input.scope}:${it.fingerprint}`,
      source,
      externalId: `${input.scope}:${it.fingerprint}`,
      identifiers,
      title: clean(it.title),
      canonicalIds: [...canonicalIds].slice(0, 20),
      ...(input.subject ? { subject: input.subject } : {}),
      ...(label ? { resource: { label } } : {}),
    };

    if (it.verdict === 'confirmed') {
      const raw = it.severity?.overall_severity;
      const conditions: FindingCondition[] = it.conditions
        .map((c) => ({
          kind: CONDITION_KIND[c.kind] ?? ('other' as const),
          text: clean(c.description),
          sourceKind: clean(c.kind, 50),
        }))
        .filter((c) => c.text !== '')
        .slice(0, MAX_FINDING_CONDITIONS);
      all.push({
        ...base,
        severity: (raw !== undefined && SEVERITY[raw.toLowerCase()]) || 'Low',
        ...(raw !== undefined ? { sourceSeverity: clean(raw, 50) } : {}),
        ...(conditions.length > 0 ? { conditions } : {}),
      });
    } else {
      const openQuestions = it.blockers.map((b) => clean(b)).filter((b) => b !== '').slice(0, MAX_FINDING_OPEN_QUESTIONS);
      const plan = it.validation_plan?.deployment ? clean(it.validation_plan.deployment) : '';
      all.push({
        ...base,
        // 出し手は重大度を付けない（§8.9）。内部値 Low・sourceSeverity なし
        severity: 'Low',
        outcome: 'unverified',
        ...(openQuestions.length > 0 ? { openQuestions } : {}),
        ...(plan ? { validationPlan: plan } : {}),
      });
    }
  }

  const capped = capFindings(all);
  return {
    findings: capped.findings,
    report: {
      confirmed: capped.findings.filter((f) => f.outcome === undefined).length,
      unverified: capped.findings.filter((f) => f.outcome === 'unverified').length,
      rejected,
      unmapped: capped.findings.filter((f) => f.canonicalIds.length === 0).length,
      duplicates,
      overLimit: capped.truncated,
    },
  };
}
