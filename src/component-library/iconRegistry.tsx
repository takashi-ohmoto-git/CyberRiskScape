import {
  Activity,
  AppWindow,
  AudioLines,
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
  FileAudio,
  FileCode,
  FileLock,
  Filter,
  Fingerprint,
  HardDrive,
  Headset,
  HelpCircle,
  IdCard,
  KeyRound,
  Layers,
  ListTree,
  Mail,
  MessageCircle,
  MessagesSquare,
  Mic,
  Monitor,
  Phone,
  ScanFace,
  ScrollText,
  Server,
  Settings,
  Shield,
  ShieldCheck,
  Skull,
  Smartphone,
  User,
  UserX,
  Users,
  Volume2,
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
  'audio-lines': AudioLines,
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
  'file-audio': FileAudio,
  'file-code': FileCode,
  'file-lock': FileLock,
  filter: Filter,
  fingerprint: Fingerprint,
  'hard-drive': HardDrive,
  headset: Headset,
  'id-card': IdCard,
  'key-round': KeyRound,
  layers: Layers,
  'list-tree': ListTree,
  mail: Mail,
  'message-circle': MessageCircle,
  'messages-square': MessagesSquare,
  mic: Mic,
  monitor: Monitor,
  phone: Phone,
  'scan-face': ScanFace,
  'scroll-text': ScrollText,
  server: Server,
  settings: Settings,
  shield: Shield,
  'shield-check': ShieldCheck,
  skull: Skull,
  smartphone: Smartphone,
  user: User,
  'user-x': UserX,
  users: Users,
  'volume-2': Volume2,
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
      // eslint-disable-next-line no-restricted-syntax
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
