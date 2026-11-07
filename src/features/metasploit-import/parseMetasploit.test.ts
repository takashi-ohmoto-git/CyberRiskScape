import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { msfTimeToIso, parseHostNodeArgs, parseMetasploit } from './parseMetasploit';

const xml = readFileSync(new URL('./__fixtures__/metasploit-export.xml', import.meta.url), 'utf-8');

function hosts() {
  const r = parseMetasploit(xml);
  if (!r.ok) throw new Error(r.error);
  return r.hosts;
}

describe('parseMetasploit', () => {
  it('ホスト・サービス・脆弱性の必要な項目だけを読む（トップレベルの services は使わない）', () => {
    const hs = hosts();
    expect(hs.map((h) => h.address)).toEqual(['192.0.2.10', '192.0.2.20', '192.0.2.30']);
    expect(hs[0]).toMatchObject({ name: 'web01.example.test', state: 'alive', osName: 'Windows 7', osFlavor: 'Professional' });
    expect(hs[0].services).toEqual([
      { id: '11', port: 445, proto: 'tcp', state: 'open', name: 'smb' },
      { id: '12', port: 80, proto: 'tcp', state: 'open', name: 'http' },
    ]);
    expect(hs[0].vulns[0]).toMatchObject({
      id: '21',
      serviceId: '11',
      refs: ['CVE-2017-0144', 'MSB-MS17-010', 'URL-https://example.test/advisory?token=MSF-URL-REF'],
      attempts: [{ exploited: true, attemptedAt: '2026-11-05 03:04:00 UTC', module: 'exploit/windows/smb/ms17_010_eternalblue' }],
    });
    expect(hs[0].vulns[0].exploitedAt).toBeUndefined();
    expect(hs[1].vulns[0].exploitedAt).toBe('2026-11-05 03:05:35 UTC');
  });

  it('秘密のマーカーを含む項目は結果に出てこない', () => {
    expect(JSON.stringify(hosts())).not.toContain('MSF-SECRET-MARKER');
  });

  it('DOCTYPE・ENTITY を含む入力は拒否する', () => {
    const evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><MetasploitV5><hosts/></MetasploitV5>';
    expect(parseMetasploit(evil).ok).toBe(false);
    expect(parseMetasploit('<!ENTITY a "b"><MetasploitV5><hosts/></MetasploitV5>').ok).toBe(false);
  });

  it.each(['', '<html/>', '<MetasploitV5><generated/></MetasploitV5>', 'not xml'])('Metasploit の形式でない入力は拒否する: %s', (input) => {
    expect(parseMetasploit(input).ok).toBe(false);
  });

  it('アドレスが IP の形でないホストは数えて除く', () => {
    const r = parseMetasploit('<MetasploitV5><hosts><host><address>evil; rm</address></host><host><address>192.0.2.1</address></host></hosts></MetasploitV5>');
    expect(r.ok && r.hosts.map((h) => h.address)).toEqual(['192.0.2.1']);
    expect(r.ok && r.skippedHosts).toBe(1);
  });

  it('module は安全な文字だけのものを読む', () => {
    const r = parseMetasploit(
      '<MetasploitV5><hosts><host><address>192.0.2.1</address><vulns><vuln><name>x</name><vuln_attempts><vuln_attempt><exploited>true</exploited><module>a b\nc</module></vuln_attempt></vuln_attempts></vuln></vulns></host></hosts></MetasploitV5>',
    );
    expect(r.ok && r.hosts[0].vulns[0].attempts[0].module).toBeUndefined();
  });
});

describe('msfTimeToIso', () => {
  it.each([
    ['2026-11-05 03:04:05 UTC', '2026-11-05T03:04:05Z'],
    ['2026-11-05T03:04:05Z', '2026-11-05T03:04:05Z'],
    ['yesterday', undefined],
    [undefined, undefined],
  ])('%s → %s', (input, expected) => {
    expect(msfTimeToIso(input)).toBe(expected);
  });
});

describe('parseHostNodeArgs', () => {
  it('<IP>=<node> を対応表にする', () => {
    expect(parseHostNodeArgs(['192.0.2.10=C1', '192.0.2.20=abc'])).toEqual({ ok: true, map: { '192.0.2.10': 'C1', '192.0.2.20': 'abc' } });
  });
  it.each(['192.0.2.10', '=C1', '192.0.2.10=', 'host name=C1'])('形が不正なら拒否する: %s', (arg) => {
    expect(parseHostNodeArgs([arg]).ok).toBe(false);
  });
});
