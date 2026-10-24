import type { DiagramBoundary, DiagramEdge, DiagramNode, LayerData } from '../../core/model/types';
import { getLocale, translate, type TranslationKey } from '../../i18n';

/**
 * ASM・偵察ツール（Shodan・ScopeSentry 等）の観測結果から、インターネットに露出したサービスの構成図の下書きを作る共通部分。
 * 製品ごとの入力の読み替え（`shodanToLayer` / `scopesentryToLayer`）は `ExposedService` に正規化して渡す。
 *
 * 方針：
 * - **脅威の知識を持たない。** サービスをノード型・攻撃面属性・線の属性に置き換えるだけで、判定は既存のルールに任せる。
 *   外から確かめられない値（認証）は保守的な既定にし、利用者が直す前提。
 * - 1 サービス（ip:port/transport）＝ 1 ノード。同じサービスが複数あれば observedAt が最新のものを採る
 * - ics タグ → IOT ／ ai タグ・Ollama 等 → LLM ／ database タグ・DB ポート → DATA_STORE ／
 *   vpn タグ・リモートアクセス用ポート → GATEWAY ／ HTTP → FRONT_END_SERVER ／ それ以外 → PROCESS
 * - 攻撃者 → 各サービスの線（Internet・TLS の有無で暗号化を判定）。WAF が報告されていれば hasWafProtection
 * - cves（製品側が報告した脆弱性の識別子）は ID だけを「未検証」として説明欄に書く
 */

const MAX_SERVICES = 300;
const MAX_CVES = 10;
const PER_COLUMN = 4;

const ICS_TAG = 'ics';
export const LLM_PRODUCT = /ollama|vllm|llama\.cpp|text-generation|localai/i;
const LLM_PORTS = new Set([11434]);
const DATA_STORE_PORTS = new Set([1433, 1521, 3306, 5432, 5984, 6379, 7474, 9042, 9200, 9300, 11211, 27017]);
const REMOTE_ACCESS_PORTS = new Set([22, 23, 445, 3389, 5900, 5901, 5902, 5903, 5938, 5985, 5986]);
const HTTP_PORTS = new Set([80, 443, 8080, 8443]);
/** 線のラベルに使う、リモートアクセス用ポートの通称。 */
const PORT_NAMES: Record<number, string> = {
  22: 'SSH',
  23: 'Telnet',
  445: 'SMB',
  3389: 'RDP',
  5900: 'VNC',
  5901: 'VNC',
  5902: 'VNC',
  5903: 'VNC',
  5938: 'TeamViewer',
  5985: 'WinRM',
  5986: 'WinRM',
};

/** 製品ごとの入力を正規化した、インターネットに露出した 1 サービス。 */
export interface ExposedService {
  ip: string;
  port: number;
  /** 既定 tcp */
  transport?: string;
  hostnames?: string[];
  product?: string;
  version?: string;
  tags?: string[];
  /** 製品側が報告した脆弱性の識別子（CVE ID 等）。重複は除き昇順で書く。 */
  cves?: string[];
  /** HTTP(S) サービスか（ポート番号が HTTP 系でも真になる）。 */
  isHttp?: boolean;
  hasTls?: boolean;
  hasWaf?: boolean;
  /** 観測日時（ISO 風の文字列。同一サービスの新旧比較と「観測日」に使う）。 */
  observedAt?: string;
  /** 線のラベル用のサービス名（製品名が無いときの代替）。 */
  serviceHint?: string;
  /** 説明欄に追記する、翻訳済みの注記（観測日の後ろ・脆弱性の前に並ぶ）。 */
  notes?: string[];
}

/** サービス以外に、露出エリアへ置くだけのノード（線は引かない）。 */
export type ExtraNode = Pick<DiagramNode, 'id' | 'type' | 'label' | 'description'>;

export interface AsmOptions {
  /** ID と i18n キーの接頭辞（`shodan` / `scopesentry`）。`<prefix>.templateName` 等のキーが必要。 */
  prefix: string;
  extraNodes?: ExtraNode[];
}

export interface AsmSummary {
  services: number;
  hosts: number;
  cves: number;
  truncated: number;
}

const safeId = (s: string) => s.replace(/[^\w-]/g, '_');
const transportOf = (s: ExposedService) => s.transport || 'tcp';
const keyOf = (s: ExposedService) => `${s.ip}:${s.port}/${transportOf(s)}`;

/** IPv4 は数値順、それ以外は文字列順（IPv4 が先）。 */
function compareIp(a: string, b: string): number {
  const v4 = (s: string) => (/^\d{1,3}(\.\d{1,3}){3}$/.test(s) ? s.split('.').map(Number) : null);
  const pa = v4(a);
  const pb = v4(b);
  if (pa && pb) return pa[0] - pb[0] || pa[1] - pb[1] || pa[2] - pb[2] || pa[3] - pb[3];
  if (pa) return -1;
  if (pb) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

function classify(s: ExposedService): DiagramNode['type'] {
  const tags = s.tags ?? [];
  const product = s.product ?? '';
  if (tags.includes(ICS_TAG)) return 'IOT';
  if (tags.includes('ai') || LLM_PRODUCT.test(product) || LLM_PORTS.has(s.port)) return 'LLM';
  if (tags.includes('database') || DATA_STORE_PORTS.has(s.port)) return 'DATA_STORE';
  if (tags.includes('vpn')) return 'GATEWAY';
  if (REMOTE_ACCESS_PORTS.has(s.port)) return 'GATEWAY';
  if (s.isHttp || HTTP_PORTS.has(s.port)) return 'FRONT_END_SERVER';
  return 'PROCESS';
}

/** 正規化したサービスから図を作る。`input` は 1 件以上（空の判定とエラー文言は呼び出し側）。 */
export function asmToLayer(input: ExposedService[], options: AsmOptions): { layer: LayerData; summary: AsmSummary } {
  const { prefix, extraNodes = [] } = options;
  const locale = getLocale();
  const t = (key: string, params?: Record<string, string | number>) => translate(`${prefix}.${key}` as TranslationKey, locale, params);

  const latest = new Map<string, ExposedService>();
  for (const s of input) {
    const prev = latest.get(keyOf(s));
    if (!prev || (s.observedAt ?? '') >= (prev.observedAt ?? '')) latest.set(keyOf(s), s);
  }

  const sorted = [...latest.values()].sort((a, b) => compareIp(a.ip, b.ip) || a.port - b.port || (transportOf(a) < transportOf(b) ? -1 : 1));
  const services = sorted.slice(0, MAX_SERVICES);
  const truncated = sorted.length - services.length;

  const nodes: DiagramNode[] = [];
  const edges: DiagramEdge[] = [];
  const ROW = 180;
  const COLW = 260;
  const TOP = 120;
  const SERVICE_X = 400;

  // 配置：ホスト順・ポート順に上から PER_COLUMN 個ずつ縦に並べて右の列へ折り返す。攻撃者（左）からの線が手前の列の
  // ノードを貫かないよう、奇数列は半段ずらす。
  let row = 0;
  let col = 0;
  const place = () => {
    if (row === PER_COLUMN) {
      col++;
      row = 0;
    }
    const pos = { x: SERVICE_X + col * COLW, y: TOP + row * ROW + (col % 2) * (ROW / 2) };
    row++;
    return pos;
  };

  const allCves = new Set<string>();
  services.forEach((s) => {
    const { x, y } = place();
    const type = classify(s);
    const transport = transportOf(s);
    const suffix = `${safeId(s.ip)}-${s.port}-${transport}`;
    const product = s.product?.trim();
    const cves = [...new Set(s.cves ?? [])].sort();
    cves.forEach((c) => allCves.add(c));
    const shown = cves.slice(0, MAX_CVES).join(', ');
    const date = s.observedAt?.match(/^\d{4}-\d{2}-\d{2}/)?.[0];
    const description = [
      type === 'IOT' && (s.tags ?? []).includes(ICS_TAG) ? t('desc.ics') : '',
      t('desc.ip', { ip: s.ip }),
      t('desc.port', { port: s.port, transport }),
      product ? t('desc.product', { product: [product, s.version].filter(Boolean).join(' ') }) : '',
      s.tags?.length ? t('desc.tags', { tags: s.tags.join(', ') }) : '',
      date ? t('desc.observed', { date }) : '',
      ...(s.notes ?? []),
      cves.length ? t('desc.cves', { ids: cves.length > MAX_CVES ? `${shown} ${t('desc.more', { n: cves.length - MAX_CVES })}` : shown }) : '',
    ]
      .filter(Boolean)
      .join(' ／ ');

    const exposes = type === 'FRONT_END_SERVER' || type === 'GATEWAY';
    const id = `${prefix}-${suffix}`;
    nodes.push({
      id,
      type,
      x,
      y,
      label: `${s.hostnames?.[0] ?? s.ip}:${s.port}${product ? ` ${product}` : ''}`,
      description,
      ...(exposes ? { attackSurface: { hasGlobalIp: true, ...(s.hasWaf ? { hasWafProtection: true } : {}) } } : {}),
    });

    const serviceName = `${PORT_NAMES[s.port] ?? product ?? s.serviceHint ?? transport} ${s.port}/${transport}`;
    edges.push({
      id: `${prefix}-e-${suffix}`,
      source: `${prefix}-actor`,
      target: id,
      network: 'Internet',
      encryption: s.hasTls ? 'TLS' : 'Plain',
      // 外から認証の有無は確かめられないため保守的に Password とする（利用者が実態に合わせて直す）。
      auth: 'Password',
      dataFlow: 'bidirectional',
      dataFlowName: serviceName.slice(0, 80),
    });
  });

  // 露出エリアに置くだけのノード（線は引かない）。サービスの後ろの枠に続けて並べる。
  extraNodes.forEach((n) => nodes.push({ ...n, ...place() }));

  const ys = nodes.map((n) => n.y);
  nodes.unshift({
    id: `${prefix}-actor`,
    type: 'THREAT_ACTOR',
    x: 60,
    y: (Math.min(...ys) + Math.max(...ys)) / 2,
    label: t('node.actor'),
    threatActorType: 'CyberCriminals',
  });

  // 境界：攻撃者を Internet（RECT）で、露出サービス全体を Public Area（ROUNDED・Internet）で囲む。
  const PAD = 40;
  const box = (id: string, members: DiagramNode[], type: DiagramBoundary['type'], extra: Partial<DiagramBoundary> = {}): DiagramBoundary => {
    const x = Math.min(...members.map((n) => n.x)) - PAD;
    const y = Math.min(...members.map((n) => n.y)) - PAD - 30;
    return {
      id,
      type,
      x,
      y,
      width: Math.max(...members.map((n) => n.x + 128)) + PAD - x,
      height: Math.max(...members.map((n) => n.y + 96)) + PAD - y,
      trustLevel: 'Internet',
      ...extra,
    };
  };
  const boundaries = [
    box(`${prefix}-b-internet`, nodes.slice(0, 1), 'RECT'),
    box(`${prefix}-b-exposed`, nodes.slice(1), 'ROUNDED', { macroTrust: 'Public Area' }),
  ];

  return {
    layer: { nodes, edges, boundaries, annotations: [] },
    summary: {
      services: services.length,
      hosts: new Set(services.map((s) => s.ip)).size,
      cves: allCves.size,
      truncated,
    },
  };
}
