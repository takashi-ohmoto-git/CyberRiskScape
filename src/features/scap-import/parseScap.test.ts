import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseScap } from './parseScap';

const read = (name: string) => readFileSync(new URL(`./__fixtures__/${name}`, import.meta.url), 'utf-8');

function ok(xml: string) {
  const r = parseScap(xml);
  if (!r.ok) throw new Error(r.error);
  return r;
}

describe('parseScap', () => {
  it('ルート要素で形式を判定する', () => {
    expect(ok(read('xccdf-results.xml')).format).toBe('xccdf');
    expect(ok(read('arf.xml')).format).toBe('arf');
    expect(ok(read('oval-results.xml')).format).toBe('oval');
    expect(parseScap('<foo/>').ok).toBe(false);
    expect(parseScap('').ok).toBe(false);
  });

  it('DOCTYPE・ENTITY を含む入力は拒否する', () => {
    const evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"/>';
    const r = parseScap(evil);
    expect(r.ok).toBe(false);
    expect(parseScap('<!ENTITY a "b"><TestResult/>').ok).toBe(false);
  });

  describe('XCCDF', () => {
    const host = ok(read('xccdf-results.xml')).hosts[0];

    it('ホスト・製品・観測時刻を読む（test-system の CPE から OpenSCAP とバージョン）', () => {
      expect(host).toMatchObject({
        scope: 'web01.example.internal',
        ips: ['192.0.2.10'],
        product: 'OpenSCAP',
        productVersion: '1.3.8',
        observedAt: '2026-10-30T10:00:00+00:00',
      });
    });

    it('入れ子の Group の中の Rule から title・ident を引き、fail だけ残す', () => {
      expect(host.xccdfFails.map((f) => f.idref.replace('xccdf_org.ssgproject.content_rule_', ''))).toEqual([
        'sshd_disable_root_login',
        'service_auditd_enabled',
        'package_legacy_removed',
      ]);
      const ssh = host.xccdfFails[0];
      expect(ssh.title).toBe('Disable SSH Root Login');
      expect(ssh.idents).toEqual([{ system: 'https://ncp.nist.gov/cce', value: 'CCE-80901-0' }]);
      expect(ssh.ovalRefs).toEqual(['oval:ssg-sshd_disable_root_login:def:1']);
    });

    it('rule-result の severity を優先し、無ければ Rule の severity', () => {
      expect(host.xccdfFails[0].severity).toBe('high');
      expect(host.xccdfFails[1].severity).toBe('medium');
    });

    it('結果の内訳を数える', () => {
      expect(host.counts).toEqual({ pass: 1, fail: 3, error: 1, unknown: 0, other: 1 });
    });

    it('TestResult 単体も読める', () => {
      const r = ok(
        '<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2" test-system="vendor-x"><target>h1</target>' +
          '<rule-result idref="r1"><result>fail</result></rule-result></TestResult>',
      );
      expect(r.hosts[0]).toMatchObject({ scope: 'h1', product: 'SCAP' });
      expect(r.hosts[0].xccdfFails[0].idref).toBe('r1');
    });
  });

  describe('ARF', () => {
    const host = ok(read('arf.xml')).hosts;

    it('資産に結びつけて 1 ホストにまとめる（XCCDF と OVAL）', () => {
      expect(host).toHaveLength(1);
      expect(host[0]).toMatchObject({
        scope: 'web01',
        hostnames: expect.arrayContaining(['web01']),
        fqdns: expect.arrayContaining(['web01.example.internal']),
        ips: expect.arrayContaining(['192.0.2.10']),
        product: 'OpenSCAP',
      });
      expect(host[0].xccdfFails).toHaveLength(1);
      expect(host[0].xccdfFails[0].title).toBe('Disable SSH Root Login');
      expect(host[0].ovalTrue.map((o) => o.definitionId)).toEqual([
        'oval:ssg-sshd_disable_root_login:def:1',
        'oval:com.example.demo:def:2',
      ]);
      expect(host[0].xccdfOvalRefs).toEqual(['oval:ssg-sshd_disable_root_login:def:1']);
    });
  });

  describe('OVAL', () => {
    const host = ok(read('oval-results.xml')).hosts[0];

    it('vulnerability/patch の true だけ残し、CVE・advisory を読む', () => {
      expect(host.scope).toBe('db01.example.internal');
      expect(host.ips).toEqual(['192.0.2.20']);
      expect(host).toMatchObject({ product: 'OpenSCAP', productVersion: '1.3.8' });
      expect(host.ovalTrue).toEqual([
        {
          definitionId: 'oval:com.example.demo:def:10',
          class: 'vulnerability',
          title: 'Demo openssl flaw',
          cves: ['CVE-2099-2222'],
          severity: 'Important',
        },
        { definitionId: 'oval:com.example.demo:def:12', class: 'patch', title: 'Demo errata patch', cves: [], severity: 'Moderate' },
      ]);
    });
  });
});
