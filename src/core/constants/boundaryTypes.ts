import type {
  BoundaryTypeId,
  MacroTrustAttribute,
  MicroTrustAttribute,
  TrustLevel,
} from '../model/types';

export interface BoundaryTypeConfig {
  id: BoundaryTypeId;
  name: string;
  isDashed: boolean;
  rounded: boolean;
}

export const BOUNDARY_TYPES: Record<BoundaryTypeId, BoundaryTypeConfig> = {
  RECT: { id: 'RECT', name: '外部境界', isDashed: false, rounded: false },
  RECT_DASHED: { id: 'RECT_DASHED', name: 'DMZ', isDashed: true, rounded: false },
  ROUNDED: { id: 'ROUNDED', name: 'マクロセグメンテーション', isDashed: false, rounded: true },
  ROUNDED_DASHED: {
    id: 'ROUNDED_DASHED',
    name: 'マイクロセグメンテーション',
    isDashed: true,
    rounded: true,
  },
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
