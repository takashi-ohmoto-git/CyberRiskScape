import {
  Activity,
  AppWindow,
  Bot,
  Box,
  Building2,
  Circle,
  Cloud,
  CloudCog,
  CloudOff,
  Cloudy,
  Cog,
  Cpu,
  Database,
  EyeOff,
  File,
  FileCode,
  Filter,
  FileLock,
  HardDrive,
  HelpCircle,
  IdCard,
  KeyRound,
  Layers,
  Mail,
  MessageCircle,
  Monitor,
  ScrollText,
  Server,
  Settings,
  Shield,
  ShieldCheck,
  Skull,
  Smartphone,
  User,
  Users,
  UserX,
  Wifi,
  type LucideIcon,
} from 'lucide-react';
import { cloneElement, createElement, type ReactElement } from 'react';
import type { IconSpec } from './schema/component';

/**
 * lucide-react のアイコンを kebab-case 名で参照するための表。
 * 新しいビルトインアイコンを使いたい場合はここに追加する。
 *
 * ※ YAML 側に書く名前は kebab-case で統一（lucide 公式サイトの URL 表記と一致）。
 */
const BUILTIN_ICONS: Record<string, LucideIcon> = {
  activity: Activity,
  'app-window': AppWindow,
  bot: Bot,
  box: Box,
  'building-2': Building2,
  circle: Circle,
  cloud: Cloud,
  'cloud-cog': CloudCog,
  'cloud-off': CloudOff,
  cloudy: Cloudy,
  cog: Cog,
  cpu: Cpu,
  database: Database,
  'eye-off': EyeOff,
  file: File,
  'file-code': FileCode,
  filter: Filter,
  'file-lock': FileLock,
  'hard-drive': HardDrive,
  'id-card': IdCard,
  'key-round': KeyRound,
  layers: Layers,
  mail: Mail,
  'message-circle': MessageCircle,
  monitor: Monitor,
  'scroll-text': ScrollText,
  server: Server,
  settings: Settings,
  shield: Shield,
  'shield-check': ShieldCheck,
  skull: Skull,
  smartphone: Smartphone,
  user: User,
  users: Users,
  'user-x': UserX,
  wifi: Wifi,
};

const FALLBACK_ICON: LucideIcon = HelpCircle;

/**
 * ビルトインアイコン名が登録済みかチェック。
 * ローダーの整合性検証で利用する（未知名は warn ログ）。
 */
export function isKnownBuiltinIcon(name: string): boolean {
  return name in BUILTIN_ICONS;
}

/**
 * `IconSpec` を React 要素に解決する。
 * - builtin: 名前未登録なら `HelpCircle` にフォールバック
 * - svg: `<span>` で innerHTML 描画（Step 3 でサニタイズ層を入れるまではビルトイン非使用前提）
 */
export function renderIcon(spec: IconSpec, props?: { size?: number; className?: string }): ReactElement {
  if (spec.kind === 'builtin') {
    const Icon = BUILTIN_ICONS[spec.name] ?? FALLBACK_ICON;
    return createElement(Icon, props);
  }
  // kind === 'svg'
  // NOTE: ビルトインライブラリは builtin name のみ使用。ユーザー由来 SVG の安全な
  // サニタイズは Step 3（YAML アップロード機能）で別途導入する。
  return (
    <span
      className={props?.className}
      style={props?.size ? { width: props.size, height: props.size, display: 'inline-block' } : undefined}
      // eslint-disable-next-line react/no-danger
      dangerouslySetInnerHTML={{ __html: spec.svg }}
    />
  );
}

/**
 * 既に作られたアイコン要素にサイズ/クラスを乗せたい場合のヘルパ。
 * （現状の `cloneElement(comp.icon, { size: 14 })` 等価のフロー）
 */
export function withIconProps(element: ReactElement, props: { size?: number; className?: string }): ReactElement {
  return cloneElement(element, props);
}
