import type {
  AgentAssetInventoryItem,
  AuthType,
  ComponentTypeId,
  EncryptionType,
  EnvVarInventoryItem,
  LayerData,
  NodePosture,
  PackageInventoryItem,
} from '../../core/model/types';
import type { TranslationKey } from '../../i18n';

/**
 * import-repo の図（1 レイヤー）から、エージェントのダッシュボードに出す中身を集める純粋関数。
 * 画面（モーダル）と CLI（`import-repo --dashboard` の単体 HTML）で共有する。
 *
 * - 材料は図の要素とインベントリだけ（取り込み時に秘密情報は捨て済み。ここで新たに読むものは無い）
 * - 文言は持たない。警告は i18n のキーと補間値で返し、表示側で訳す
 * - 図を利用者が編集した後でも動くよう、ID ではなく型・インベントリ・線の属性で拾う
 */

export interface RepoDashboardAlert {
  level: 'high' | 'medium';
  key: TranslationKey;
  params?: Record<string, string | number>;
}

export interface RepoDashboardData {
  repoName?: string;
  collectedAt?: string;
  agent: {
    label: string;
    allowCount: number;
    denyCount: number;
    tools: string[];
    broadAllows: string[];
    sandbox: boolean;
    hooks: boolean;
  };
  skills: string[];
  commands: string[];
  mcpServers: Array<{
    id: string;
    label: string;
    description?: string;
    /** エージェントからの線が Internet 経由か。 */
    internet: boolean;
    auth?: AuthType;
    encryption?: EncryptionType;
  }>;
  manifests: Array<{
    id: string;
    label: string;
    kind: 'npm' | 'pypi';
    posture?: NodePosture;
    packages: PackageInventoryItem[];
  }>;
  envFiles: Array<{
    id: string;
    label: string;
    template: boolean;
    gitIgnored?: boolean;
    items: EnvVarInventoryItem[];
  }>;
  /** Internet 経由の線でつながる相手（レジストリ・リモート MCP 等）。 */
  external: Array<{ id: string; label: string; type: ComponentTypeId; encryption: EncryptionType }>;
  alerts: RepoDashboardAlert[];
}

/** インストールスクリプトありの警告に名前を並べる上限。 */
const MAX_NAMES = 5;

/**
 * `agentId` のノードがエージェントのインベントリ（kind: 'agent'）を持たなければ undefined。
 */
export function buildRepoDashboard(layer: LayerData, agentId: string): RepoDashboardData | undefined {
  const agentNode = layer.nodes.find((n) => n.id === agentId);
  const inv = agentNode?.inventory;
  if (!agentNode || inv?.kind !== 'agent') return undefined;

  const byId = new Map(layer.nodes.map((n) => [n.id, n]));
  const alerts: RepoDashboardAlert[] = [];
  const names = (kind: AgentAssetInventoryItem['kind']) => inv.items.filter((i) => i.kind === kind).map((i) => i.name);

  if (inv.broadAllows.length > 0) {
    alerts.push({ level: 'high', key: 'repoDashboard.alert.broadAllow', params: { entries: inv.broadAllows.join(', ') } });
  }
  if (!inv.sandbox) alerts.push({ level: 'medium', key: 'repoDashboard.alert.sandboxUnset' });

  const mcpServers: RepoDashboardData['mcpServers'] = [];
  for (const n of layer.nodes) {
    if (n.type !== 'MCP_SERVER') continue;
    const e = layer.edges.find((x) => (x.source === agentId && x.target === n.id) || (x.target === agentId && x.source === n.id));
    const internet = e?.network === 'Internet';
    mcpServers.push({
      id: n.id,
      label: n.label ?? n.id,
      ...(n.description ? { description: n.description } : {}),
      internet,
      ...(e ? { auth: e.auth, encryption: e.encryption } : {}),
    });
    if (internet && e?.auth === 'None') {
      alerts.push({ level: 'high', key: 'repoDashboard.alert.mcpNoAuth', params: { name: n.label ?? n.id } });
    }
  }

  const manifests: RepoDashboardData['manifests'] = [];
  const envFiles: RepoDashboardData['envFiles'] = [];
  for (const n of layer.nodes) {
    const i = n.inventory;
    if (!i) continue;
    const label = n.label ?? n.id;
    if (i.kind === 'npm' || i.kind === 'pypi') {
      manifests.push({ id: n.id, label, kind: i.kind, ...(n.posture ? { posture: n.posture } : {}), packages: i.items });
      const scripts = i.items.filter((p) => p.hasInstallScript).map((p) => p.name);
      if (scripts.length > 0 && n.posture?.installScripts !== 'Disabled') {
        const shown = scripts.slice(0, MAX_NAMES).join(', ') + (scripts.length > MAX_NAMES ? ', …' : '');
        alerts.push({
          level: 'medium',
          key: 'repoDashboard.alert.installScripts',
          params: { source: label, count: scripts.length, names: shown },
        });
      }
      if (n.posture?.dependencyLockfile !== 'Locked') {
        alerts.push({ level: 'medium', key: 'repoDashboard.alert.unlocked', params: { source: label } });
      }
    } else if (i.kind === 'env') {
      envFiles.push({
        id: n.id,
        label,
        template: i.template,
        ...(i.gitIgnored === undefined ? {} : { gitIgnored: i.gitIgnored }),
        items: i.items,
      });
      if (!i.template && i.gitIgnored === false) {
        alerts.push({ level: 'high', key: 'repoDashboard.alert.envTracked', params: { source: label } });
      }
    }
  }

  const external: RepoDashboardData['external'] = [];
  const seen = new Set<string>();
  for (const e of layer.edges) {
    if (e.network !== 'Internet') continue;
    for (const id of [e.source, e.target]) {
      const n = byId.get(id);
      // 端末内の要素（エージェント・依存）は相手側ではない
      if (!n || seen.has(id) || n.type === 'AGENT' || n.type === 'PACKAGE_DEPENDENCIES' || n.type === 'PC') continue;
      seen.add(id);
      external.push({ id, label: n.label ?? id, type: n.type, encryption: e.encryption });
      if (e.encryption === 'Plain') {
        alerts.push({ level: 'high', key: 'repoDashboard.alert.plainExternal', params: { name: n.label ?? id } });
      }
    }
  }

  alerts.sort((a, b) => (a.level === b.level ? 0 : a.level === 'high' ? -1 : 1));

  const repoName = layer.nodes.find((n) => n.type === 'SOURCE_CODE')?.label;
  return {
    ...(repoName ? { repoName } : {}),
    collectedAt: inv.collectedAt,
    agent: {
      label: agentNode.label ?? agentNode.id,
      allowCount: inv.allowCount,
      denyCount: inv.denyCount,
      tools: inv.tools,
      broadAllows: inv.broadAllows,
      sandbox: inv.sandbox,
      hooks: inv.hooks,
    },
    skills: names('skill'),
    commands: names('command'),
    mcpServers,
    manifests,
    envFiles,
    external,
    alerts,
  };
}
