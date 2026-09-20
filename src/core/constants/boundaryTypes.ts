import type {
  BoundaryTypeId,
  MacroTrustAttribute,
  MicroTrustAttribute,
  TrustLevel,
} from '../model/types';
import type { TranslationKey } from '../../i18n';

export interface BoundaryTypeConfig {
  id: BoundaryTypeId;
  nameKey: TranslationKey;
  /**
   * 枠線の破線指定。`fine` はマイクロセグメンテーション相当、`coarse` はそれより粗い。
   * CSS の `border-style: dashed` は破線長を直接指定できず線幅に比例するため、
   * `coarse` は線幅を上げて表現する（クラスへの解決は `BOUNDARY_DASH_CLASS`）。
   */
  dash: 'none' | 'fine' | 'coarse';
  rounded: boolean;
}

export const BOUNDARY_TYPES: Record<BoundaryTypeId, BoundaryTypeConfig> = {
  RECT: { id: 'RECT', nameKey: 'canvas.boundaryType.rect', dash: 'none', rounded: false },
  RECT_DASHED: { id: 'RECT_DASHED', nameKey: 'canvas.boundaryType.dmz', dash: 'fine', rounded: false },
  ROUNDED: { id: 'ROUNDED', nameKey: 'canvas.boundaryType.macro', dash: 'none', rounded: true },
  ROUNDED_DASHED: {
    id: 'ROUNDED_DASHED',
    nameKey: 'canvas.boundaryType.micro',
    dash: 'fine',
    rounded: true,
  },
  BLAST_RADIUS: {
    id: 'BLAST_RADIUS',
    nameKey: 'canvas.boundaryType.blastRadius',
    dash: 'coarse',
    rounded: true,
  },
};

/**
 * 枠線の破線指定を Tailwind クラスへ解決する（キャンバス描画と凡例で共有）。
 * JIT の purge 対策でクラス名は合成せずフル文字列で持つ（DesignPrinciples §4.1）。
 */
export const BOUNDARY_DASH_CLASS: Record<BoundaryTypeConfig['dash'], string> = {
  none: 'border-2 border-solid',
  fine: 'border-2 border-dashed',
  coarse: 'border-4 border-dashed',
};

/**
 * マクロセグメンテーションの TRUST ATTRIBUTE → 脅威エンジン内部の TrustLevel マッピング。
 * Public Area は外部接点扱い (Internet)、Office/Security は社内扱い (Internal)。
 */
export const MACRO_TRUST_TO_TRUST_LEVEL: Record<MacroTrustAttribute, TrustLevel> = {
  'Public Area': 'Internet',
  'Office Area': 'Internal',
  'Security Zone': 'Internal',
};

/**
 * マイクロセグメンテーションの TRUST ATTRIBUTE → 脅威エンジン内部の TrustLevel マッピング。
 * Dev/Staging/Prod は全て社内 (Internal) として扱う（区別は属性側で表現）。
 */
export const MICRO_TRUST_TO_TRUST_LEVEL: Record<MicroTrustAttribute, TrustLevel> = {
  Development: 'Internal',
  Staging: 'Internal',
  Production: 'Internal',
};
