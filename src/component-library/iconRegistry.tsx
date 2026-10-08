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
  ClipboardCheck,
  ClipboardPen,
  CloudOff,
  Cloudy,
  Cog,
  Container,
  Cpu,
  CreditCard,
  Database,
  EyeOff,
  File,
  FileAudio,
  FileCode,
  FileJson,
  FileLock,
  Filter,
  Fingerprint,
  HardDrive,
  Headset,
  HelpCircle,
  IdCard,
  KeyRound,
  KeySquare,
  Layers,
  LockKeyhole,
  ListTree,
  Mail,
  MessageCircle,
  MessagesSquare,
  Mic,
  MousePointerClick,
  Monitor,
  Phone,
  Puzzle,
  PhoneCall,
  ScanFace,
  ScrollText,
  Send,
  Server,
  ServerCog,
  Settings,
  Shield,
  ShieldCheck,
  ShieldHalf,
  Skull,
  SlidersHorizontal,
  Smartphone,
  User,
  UserCog,
  UserX,
  Users,
  Vault,
  Volume2,
  Wifi,
  Workflow,
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
  'clipboard-check': ClipboardCheck,
  'clipboard-pen': ClipboardPen,
  'cloud-off': CloudOff,
  cloudy: Cloudy,
  cog: Cog,
  container: Container,
  cpu: Cpu,
  'credit-card': CreditCard,
  database: Database,
  'eye-off': EyeOff,
  file: File,
  'file-audio': FileAudio,
  'file-code': FileCode,
  'file-json': FileJson,
  'file-lock': FileLock,
  filter: Filter,
  fingerprint: Fingerprint,
  'hard-drive': HardDrive,
  headset: Headset,
  'id-card': IdCard,
  'key-round': KeyRound,
  'key-square': KeySquare,
  layers: Layers,
  'list-tree': ListTree,
  'lock-keyhole': LockKeyhole,
  mail: Mail,
  'message-circle': MessageCircle,
  'messages-square': MessagesSquare,
  mic: Mic,
  'mouse-pointer-click': MousePointerClick,
  monitor: Monitor,
  phone: Phone,
  'phone-call': PhoneCall,
  puzzle: Puzzle,
  'scan-face': ScanFace,
  'scroll-text': ScrollText,
  send: Send,
  server: Server,
  'server-cog': ServerCog,
  settings: Settings,
  shield: Shield,
  'shield-check': ShieldCheck,
  'shield-half': ShieldHalf,
  skull: Skull,
  'sliders-horizontal': SlidersHorizontal,
  smartphone: Smartphone,
  user: User,
  'user-cog': UserCog,
  'user-x': UserX,
  users: Users,
  vault: Vault,
  'volume-2': Volume2,
  wifi: Wifi,
  workflow: Workflow,
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
