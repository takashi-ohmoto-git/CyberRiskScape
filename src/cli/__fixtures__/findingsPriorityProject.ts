import { readFileSync } from 'node:fs';

/** findings-priority / import-kev のテスト用の架空のプロジェクト（攻撃者 → 公開サーバー(C2) → DB(C3) → 個人情報(C4)）。 */
const base = JSON.parse(readFileSync(new URL('./sample-project.json', import.meta.url), 'utf-8')) as { layers: object; idCounters: object };

export function makeProject(findings: object[], opts: { attacker?: boolean } = {}): object {
  const attacker = opts.attacker === false ? [] : [{ id: 'atk', seq: 1, type: 'AGENTIC_ATTACKER', x: 0, y: 0, label: '攻撃者' }];
  const edge = (id: string, source: string, target: string) => ({ id, source, target, auth: 'MFA', network: 'VPC', encryption: 'TLS' });
  return {
    ...base,
    layers: {
      ...base.layers,
      L1: {
        nodes: [
          ...attacker,
          {
            id: 'web',
            seq: 2,
            type: 'FRONT_END_SERVER',
            x: 0,
            y: 0,
            label: '公開サーバー',
            attackSurface: { hasGlobalIp: true, hasUserAuthentication: true, hasSourceIpRestriction: true, hasRemoteAccessRestriction: true, hasWafProtection: true },
          },
          { id: 'mid', seq: 3, type: 'DB', x: 0, y: 0, label: '業務 DB' },
          { id: 'pii', seq: 4, type: 'PERSONAL_INFO', x: 0, y: 0, label: '顧客情報' },
        ],
        edges: [edge('e1', 'web', 'mid'), edge('e2', 'mid', 'pii')],
        boundaries: [],
      },
    },
    activeLayer: 'L1',
    idCounters: { ...base.idCounters, L1: { node: 4, edge: 2, boundary: 0 } },
    findings,
  };
}

export function cveFinding(id: string, nodeId: string, severity: string, cve: string, extra: object = {}): object {
  return {
    id,
    source: { format: 'cyclonedx', product: 'example-scanner', importedAt: '2026-11-01T00:00:00Z' },
    externalId: id,
    identifiers: [{ scheme: 'cve', value: cve }],
    title: `${cve} の指摘`,
    severity,
    canonicalIds: [],
    subject: { layer: 'L1', nodeId },
    ...extra,
  };
}

