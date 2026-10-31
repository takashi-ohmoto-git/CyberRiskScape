import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseScap, type ParseScapResult } from './parseScap';
import { scapToFindings } from './scapToFindings';
import { BUNDLED_XCCDF_MAP } from './xccdfMap';
import type { ImportNodeRef } from '../findings-import/resolveNode';

const read = (name: string) => readFileSync(new URL(`./__fixtures__/${name}`, import.meta.url), 'utf-8');
const NODES: ImportNodeRef[] = [
  { id: 'n-web', layer: 'L1', seq: 1, type: 'FRONT_END_SERVER' },
  { id: 'n-db', layer: 'L1', seq: 2, type: 'DATABASE' },
];
const AT = '2026-10-31T00:00:00.000Z';

function convert(file: string, extra: { nodeMap?: Record<string, string>; nodeRef?: string } = {}) {
  const parsed: ParseScapResult = parseScap(read(file));
  if (!parsed.ok) throw new Error(parsed.error);
  return scapToFindings({ format: parsed.format, hosts: parsed.hosts, map: BUNDLED_XCCDF_MAP, nodes: NODES, importedAt: AT, ...extra });
}

describe('scapToFindings', () => {
  it('XCCDF：fail だけを指摘にし、識別子・深刻度・canonicalId・出どころを付ける', () => {
    const out = convert('xccdf-results.xml', { nodeRef: 'C1' });
    expect(out.findings).toHaveLength(3);
    const ssh = out.findings[0];
    expect(ssh).toMatchObject({
      id: 'OpenSCAP:web01.example.internal:xccdf_org.ssgproject.content_rule_sshd_disable_root_login',
      severity: 'High',
      sourceSeverity: 'high',
      title: 'Disable SSH Root Login',
      canonicalIds: ['process-privilege-escalation'],
      subject: { layer: 'L1', nodeId: 'n-web' },
      resource: { label: 'web01.example.internal', type: 'host' },
      observedAt: '2026-10-30T10:00:00+00:00',
      source: { format: 'xccdf', product: 'OpenSCAP', productVersion: '1.3.8', scope: 'web01.example.internal', importedAt: AT },
    });
    expect(ssh.identifiers).toEqual([
      { scheme: 'xccdf-rule', value: 'xccdf_org.ssgproject.content_rule_sshd_disable_root_login' },
      { scheme: 'cce', value: 'CCE-80901-0' },
      { scheme: 'oval-def', value: 'oval:ssg-sshd_disable_root_login:def:1' },
    ]);
    const legacy = out.findings[2];
    expect(legacy.identifiers.map((i) => i.scheme)).toEqual(['xccdf-rule', 'cve']);
    expect(legacy.severity).toBe('Low');
    expect(legacy.canonicalIds).toEqual([]);
    expect(out.perHost[0].unmapped.map((u) => u.id)).toEqual(['xccdf_org.ssgproject.content_rule_package_legacy_removed']);
  });

  it('ARF：XCCDF の check が参照する OVAL 定義は二重に数えない', () => {
    const out = convert('arf.xml', { nodeRef: 'n-web' });
    expect(out.findings.map((f) => f.identifiers[0])).toEqual([
      { scheme: 'xccdf-rule', value: 'xccdf_org.ssgproject.content_rule_sshd_disable_root_login' },
      { scheme: 'oval-def', value: 'oval:com.example.demo:def:2' },
    ]);
    expect(out.findings.every((f) => f.source.format === 'arf')).toBe(true);
    const oval = out.findings[1];
    expect(oval).toMatchObject({ severity: 'Critical', canonicalIds: ['known-vulnerability-unpatched'] });
    expect(oval.identifiers[1]).toEqual({ scheme: 'cve', value: 'CVE-2099-1111' });
    // 資産の情報で scope が決まる
    expect(out.findings[0].source.scope).toBe('web01');
  });

  it('OVAL：vulnerability/patch の true だけ。advisory の深刻度を正規化する', () => {
    const out = convert('oval-results.xml', { nodeMap: { '192.0.2.20': 'C2' } });
    expect(out.findings.map((f) => [f.identifiers[0].value, f.severity])).toEqual([
      ['oval:com.example.demo:def:10', 'High'],
      ['oval:com.example.demo:def:12', 'Medium'],
    ]);
    expect(out.findings[0].subject).toEqual({ layer: 'L1', nodeId: 'n-db' });
    expect(out.findings[0].identifiers.map((i) => i.scheme)).toEqual(['oval-def', 'cve']);
  });

  it('対応が無いホストは未結合（subject なし）で報告される', () => {
    const out = convert('xccdf-results.xml');
    expect(out.unlinkedHosts).toEqual(['web01.example.internal']);
    expect(out.findings.every((f) => f.subject === undefined)).toBe(true);
    const mapped = convert('xccdf-results.xml', { nodeMap: { web01: 'C1', 'web01.example.internal': 'C2' } });
    expect(mapped.findings[0].subject?.nodeId).toBe('n-db'); // target は hostname にも FQDN にも入る（hostname 側の web01 は当たらない）
  });
});
