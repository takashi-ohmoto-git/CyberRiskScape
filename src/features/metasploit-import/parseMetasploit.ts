import { XMLParser } from 'fast-xml-parser';

/**
 * Metasploit Framework の `db_export -f xml` を、取り込みに必要な項目だけに正規化する。純粋関数（ファイル I/O なし）。
 * convert-metasploit（台帳 YAML）と import-metasploit-assets（Asset タブ）が共有する。
 *
 * 読むのは、ホストの address・name・state・os-name・os-flavor、サービスの id・port・proto・state・name、
 * 脆弱性の id・service-id・name・exploited-at・created-at・updated-at・参照（ref）、
 * 試行（vuln_attempt）の exploited・attempted-at・module だけ。
 * notes・host_details・vuln_details・info・comments・資格情報・loot・session・fail-detail・check-detail・
 * username・resource（Ruby Marshal の Base64。復号しない）・web_*・module_details・events は読まず、写さない。
 *
 * 安全：DOCTYPE・ENTITY を含む入力は拒否し、実体の展開は無効にする（parseScap と同じ）。文字列は 200 文字で切る。
 */

const TEXT_MAX = 200;
const HOSTS_MAX = 20000;
const ITEMS_MAX = 50000;

export interface MetasploitService {
  id?: string;
  port: number;
  proto: string;
  state: string;
  name?: string;
}

export interface MetasploitAttempt {
  exploited: boolean;
  attemptedAt?: string;
  module?: string;
}

export interface MetasploitVuln {
  id?: string;
  serviceId?: string;
  name: string;
  exploitedAt?: string;
  createdAt?: string;
  updatedAt?: string;
  refs: string[];
  attempts: MetasploitAttempt[];
}

export interface MetasploitHost {
  address: string;
  name?: string;
  state?: string;
  osName?: string;
  osFlavor?: string;
  updatedAt?: string;
  services: MetasploitService[];
  vulns: MetasploitVuln[];
}

export type ParseMetasploitResult =
  | { ok: true; hosts: MetasploitHost[]; skippedHosts: number }
  | { ok: false; error: string };

type Node = Record<string, unknown>;

const REPEATED = new Set(['host', 'service', 'vuln', 'ref', 'vuln_attempt']);

const parser = new XMLParser({
  ignoreAttributes: true,
  removeNSPrefix: true,
  processEntities: false,
  htmlEntities: false,
  ignoreDeclaration: true,
  ignorePiTags: true,
  parseTagValue: false,
  parseAttributeValue: false,
  isArray: (name) => REPEATED.has(name),
});

const arr = (v: unknown): unknown[] => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);
const isNode = (v: unknown): v is Node => typeof v === 'object' && v !== null && !Array.isArray(v);
const kids = (n: unknown, key: string): Node[] => arr(isNode(n) ? n[key] : undefined).filter(isNode);

/** 要素の文字列。空白を畳んで切る。空なら undefined。 */
function text(v: unknown): string | undefined {
  const first = Array.isArray(v) ? v[0] : v;
  if (typeof first !== 'string') return undefined;
  const s = first.replace(/\s+/g, ' ').trim().slice(0, TEXT_MAX);
  return s ? s : undefined;
}

const field = (n: Node, key: string): string | undefined => text(n[key]);

/** IPv4 / IPv6 に使う文字だけで構成されたアドレス。 */
const ADDRESS_RE = /^[0-9A-Fa-f:.]{2,45}$/;

export const isAddress = (s: string): boolean => ADDRESS_RE.test(s);

/** 'YYYY-MM-DD HH:MM:SS UTC' → ISO（Z 付き）。既に ISO ならそのまま。それ以外は undefined。 */
export function msfTimeToIso(raw: string | undefined): string | undefined {
  const s = raw?.trim();
  if (!s) return undefined;
  const m = /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) UTC$/.exec(s);
  if (m) return `${m[1]}T${m[2]}Z`;
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(s) ? s.slice(0, 40) : undefined;
}

const MODULE_RE = /^[A-Za-z0-9_/.-]{1,150}$/;

function parseService(n: Node): MetasploitService | undefined {
  const port = Number(field(n, 'port'));
  if (!Number.isInteger(port) || port < 1 || port > 65535) return undefined;
  const id = field(n, 'id');
  const name = field(n, 'name');
  return {
    ...(id ? { id } : {}),
    port,
    proto: (field(n, 'proto') ?? 'tcp').toLowerCase(),
    state: (field(n, 'state') ?? '').toLowerCase(),
    ...(name ? { name: name.toLowerCase() } : {}),
  };
}

function parseVuln(n: Node): MetasploitVuln | undefined {
  const name = field(n, 'name');
  if (!name) return undefined;
  const refs = kids(n, 'refs').flatMap((r) => arr(r.ref).map(text).filter((t): t is string => t !== undefined));
  const attempts = kids(n, 'vuln_attempts').flatMap((a) =>
    arr(a.vuln_attempt)
      .filter(isNode)
      .map((v): MetasploitAttempt => {
        const mod = field(v, 'module');
        const at = field(v, 'attempted-at');
        return {
          exploited: field(v, 'exploited')?.toLowerCase() === 'true',
          ...(at ? { attemptedAt: at } : {}),
          ...(mod && MODULE_RE.test(mod) ? { module: mod } : {}),
        };
      }),
  );
  const id = field(n, 'id');
  const serviceId = field(n, 'service-id');
  const exploitedAt = field(n, 'exploited-at');
  const createdAt = field(n, 'created-at');
  const updatedAt = field(n, 'updated-at');
  return {
    ...(id ? { id } : {}),
    ...(serviceId ? { serviceId } : {}),
    name,
    ...(exploitedAt ? { exploitedAt } : {}),
    ...(createdAt ? { createdAt } : {}),
    ...(updatedAt ? { updatedAt } : {}),
    refs: refs.slice(0, 50),
    attempts: attempts.slice(0, 200),
  };
}

export function parseMetasploit(xml: string): ParseMetasploitResult {
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) {
    return { ok: false, error: 'DOCTYPE・ENTITY を含む XML は読み込みません（外部実体・実体展開の攻撃を避けるため）。' };
  }
  let doc: unknown;
  try {
    doc = parser.parse(xml);
  } catch {
    return { ok: false, error: 'XML として読み込めませんでした。' };
  }
  const rootKey = isNode(doc) ? Object.keys(doc).find((k) => /^Metasploit/i.test(k)) : undefined;
  const root = rootKey ? (doc as Node)[rootKey] : undefined;
  if (!isNode(root) || !('hosts' in root)) {
    return { ok: false, error: 'Metasploit の db_export（-f xml）の形式として読めませんでした。' };
  }

  const hosts: MetasploitHost[] = [];
  let skippedHosts = 0;
  for (const hostsEl of kids(root, 'hosts')) {
    for (const h of arr(hostsEl.host).filter(isNode)) {
      const address = field(h, 'address');
      if (!address || !isAddress(address) || hosts.length >= HOSTS_MAX) {
        skippedHosts += 1;
        continue;
      }
      const services = kids(h, 'services')
        .flatMap((s) => arr(s.service).filter(isNode))
        .map(parseService)
        .filter((s): s is MetasploitService => s !== undefined)
        .slice(0, ITEMS_MAX);
      const vulns = kids(h, 'vulns')
        .flatMap((s) => arr(s.vuln).filter(isNode))
        .map(parseVuln)
        .filter((v): v is MetasploitVuln => v !== undefined)
        .slice(0, ITEMS_MAX);
      const name = field(h, 'name');
      const state = field(h, 'state');
      const osName = field(h, 'os-name');
      const osFlavor = field(h, 'os-flavor');
      const updatedAt = field(h, 'updated-at');
      hosts.push({
        address,
        ...(name ? { name } : {}),
        ...(state ? { state } : {}),
        ...(osName ? { osName } : {}),
        ...(osFlavor ? { osFlavor } : {}),
        ...(updatedAt ? { updatedAt } : {}),
        services,
        vulns,
      });
    }
  }
  return { ok: true, hosts, skippedHosts };
}

/** `--host-node <IP>=<C番号|ID>`（繰り返し可）を対応表にする。 */
export function parseHostNodeArgs(args: readonly string[]): { ok: true; map: Record<string, string> } | { ok: false; error: string } {
  const map: Record<string, string> = {};
  for (const a of args) {
    const i = a.indexOf('=');
    const ip = i > 0 ? a.slice(0, i).trim() : '';
    const node = i > 0 ? a.slice(i + 1).trim() : '';
    if (!isAddress(ip) || !node || node.length > 200) {
      return { ok: false, error: `--host-node は <IP>=<C番号|ノード ID> の形で指定してください: ${a.slice(0, 80)}` };
    }
    map[ip] = node;
  }
  return { ok: true, map };
}
