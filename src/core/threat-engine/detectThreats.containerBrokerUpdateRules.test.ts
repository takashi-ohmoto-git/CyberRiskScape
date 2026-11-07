import { describe, expect, it } from 'vitest';
import { detectThreats } from './detectThreats';
import type { DiagramEdge, DiagramNode, NodePosture } from '../model/types';
import { BUNDLED_THREAT_LIBRARY } from '../../threat-library/loader/bundledLibrary';

/**
 * コンテナ基盤・メッセージブローカー・ソフトウェア更新サーバーの運用状況ルール（2026-11-07）の発火確認。
 * 未入力（Unknown）は悪い値と同じ扱いで発火し、良い値で消える。
 */

const fire = (id: string, nodes: DiagramNode[], edges: DiagramEdge[] = []) => {
  const rule = BUNDLED_THREAT_LIBRARY.rules.find((r) => r.id === id);
  expect(rule).toBeDefined();
  return detectThreats({ nodes, edges, framework: 'ALL', rules: [rule!] });
};

const CASES: ReadonlyArray<{
  id: string;
  type: DiagramNode['type'];
  canonicalId: string;
  bad: NodePosture;
  good: NodePosture;
}> = [
  { id: 'netinfra-container-privileged-workload-001', type: 'CONTAINER_PLATFORM', canonicalId: 'container-host-capability-exposure', bad: { workloadPrivilegeLimit: 'None' }, good: { workloadPrivilegeLimit: 'Enforced' } },
  { id: 'netinfra-container-admission-path-gap-001', type: 'CONTAINER_PLATFORM', canonicalId: 'admission-policy-path-inconsistency', bad: { admissionCoverage: 'Partial' }, good: { admissionCoverage: 'AllPaths' } },
  { id: 'netinfra-container-selector-trust-001', type: 'CONTAINER_PLATFORM', canonicalId: 'selector-trust-confusion', bad: { selectorControl: 'Open' }, good: { selectorControl: 'Restricted' } },
  { id: 'api-broker-topic-scope-001', type: 'MESSAGE_BROKER', canonicalId: 'broker-topic-scope-gap', bad: { topicAccessScope: 'Broad' }, good: { topicAccessScope: 'Restricted' } },
  { id: 'api-broker-producer-authenticity-001', type: 'MESSAGE_BROKER', canonicalId: 'webhook-signature-verification-gap', bad: { producerAuthentication: 'None' }, good: { producerAuthentication: 'Enforced' } },
  { id: 'api-broker-dead-letter-disclosure-001', type: 'MESSAGE_BROKER', canonicalId: 'dead-letter-content-disclosure', bad: { deadLetterProtection: 'None' }, good: { deadLetterProtection: 'Protected' } },
  { id: 'dev-update-signature-unverified-001', type: 'UPDATE_SERVER', canonicalId: 'update-signature-verification-gap', bad: { updateSigning: 'None' }, good: { updateSigning: 'Verified' } },
  { id: 'dev-update-rollback-binding-001', type: 'UPDATE_SERVER', canonicalId: 'update-rollback-confusion', bad: { updateRollbackProtection: 'None' }, good: { updateRollbackProtection: 'Enforced' } },
];

describe.each(CASES)('$id', ({ id, type, canonicalId, bad, good }) => {
  const node: DiagramNode = { id: 'n', type, x: 0, y: 0 };

  it('未入力は悪い値と同じ扱いで発火し、運用状況の印が付く', () => {
    const r = fire(id, [node]);
    expect(r).toHaveLength(1);
    expect(r[0].assumptionFlags).toEqual(['posture']);
  });

  it('悪い値は発火し、良い値で消える', () => {
    expect(fire(id, [{ ...node, posture: bad }])).toHaveLength(1);
    expect(fire(id, [{ ...node, posture: good }])).toHaveLength(0);
  });

  it('別の型では発火しない', () => {
    expect(fire(id, [{ id: 'd', type: 'DATABASE', x: 0, y: 0 }])).toHaveLength(0);
  });

  it('canonicalId が想定どおり', () => {
    expect(BUNDLED_THREAT_LIBRARY.rules.find((r) => r.id === id)?.canonicalId).toBe(canonicalId);
  });
});

describe('stride-connector-tampering-001', () => {
  it('CONNECTOR と MESSAGE_BROKER の両方で発火する（接続が 1 本以上ある図）', () => {
    const app: DiagramNode = { id: 'a', type: 'OTHER_APP', x: 0, y: 0 };
    const edge: DiagramEdge = { id: 'e', source: 'a', target: 'n', network: 'VPC', encryption: 'TLS', auth: 'Token' };
    for (const type of ['CONNECTOR', 'MESSAGE_BROKER'] as const) {
      expect(fire('stride-connector-tampering-001', [app, { id: 'n', type, x: 0, y: 0 }], [edge])).toHaveLength(1);
    }
  });
});
